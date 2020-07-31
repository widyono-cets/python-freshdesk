import json

import requests
from requests import HTTPError

import os
import stat
import shutil
from pathlib import Path
import pickle
import getpass

from freshdesk.v2.errors import (
    FreshserviceAccessDenied, FreshserviceBadRequest, FreshserviceError, FreshserviceNotFound, FreshserviceRateLimited,
    FreshserviceServerError, FreshserviceUnauthorized,
)
from freshdesk.v2.models import Agent, Conversation, Group, Role, Ticket, TicketField, Requester, ticket_statuses, ticket_priorities, ticket_sources, conversation_sources

from datetime import datetime, timedelta

from textwrap import TextWrapper

tw = TextWrapper(width=80,initial_indent=12*' ',subsequent_indent=12*' ')

class TicketAPI(object):
    def __init__(self, api):
        self._api = api
        self._cachedir = Path(self._api.cachedir, "tickets")
        if not self._cachedir.exists():
            try:
                os.mkdir(self._cachedir)
                os.chmod(self._cachedir, self._api.cachedirmode)
            except:
                raise AttributeError(f'Cannot create cache directory {self._cachedir}')
            if self._api.cachegroup:
                shutil.chown(self._cachedir, group=self._api.cachegroup)

    def source_name_to_id(self, name):
        return ticket_sources.index(name)

    def source_id_to_name(self, id):
        return ticket_sources[id]

    def status_name_to_id(self, name):
        return ticket_statuses.index(name)

    def status_id_to_name(self, id):
        return ticket_statuses[id]

    def priority_name_to_id(self, name):
        return ticket_priorities.index(name)

    def priority_id_to_name(self, id):
        return ticket_priorties[id]

    def id_to_cache_path(self, id):
        tid=f'{id:08}'
        # max 100 subdirectories at any level
        p=Path(tid[-2:],tid[-4:-2],tid[-6:-4],tid[:-6])
        q=Path(self._cachedir)
        for x in p.parts:
            q=Path(q,x)
            if not q.exists():
                try:
                    os.mkdir(q)
                    os.chmod(q, self._api.cachedirmode)
                except:
                    raise AttributeError(f'Cannot create cache directory {q}')
                if self._api.cachegroup:
                    shutil.chown(q, group=self._api.cachegroup)
        return Path(self._cachedir, p, str(id))

    def get_ticket(self, ticket_id, include=None):
        """Fetches the ticket for the given ticket ID"""
        _ticketcachefile = self.id_to_cache_path(ticket_id)
        new_ticketcachefile = not _ticketcachefile.exists()
        if new_ticketcachefile or any(x in ['tickets','all'] for x in self._api.updatecache):
            url = 'tickets/%d' % ticket_id
            if include:
                url = url + f"?include={include}"
            try:
                ticket = self._api._get(url)['ticket']
            except FreshserviceNotFound:
                ticket = None
            with open(_ticketcachefile, mode='wb') as f:
                pickle.dump(ticket,f)
            if new_ticketcachefile:
                os.chmod(_ticketcachefile, self._api.cachemode)
                if self._api.cachegroup:
                    shutil.chown(_ticketcachefile, group=self._api.cachegroup)
        else:
            with open(_ticketcachefile, mode='rb') as f:
                ticket = pickle.load(f)
        if ticket:
            return Ticket(**ticket)
        else:
            return None

    def create_ticket(self, subject, **kwargs):
        """
            Creates a ticket
            To create ticket with attachments,
            pass a key 'attachments' with value as list of fully qualified file paths in string format.
            ex: attachments = ('/path/to/attachment1', '/path/to/attachment2')
        """

        url = 'tickets'
        status = kwargs.get('status', 2)         # magic default value of 2 = Open
        priority = kwargs.get('priority', 1)     # magic default value of 1 = Low
        data = {
            'subject': subject,
            'status': status,
            'priority': priority,
        }
        data.update(kwargs)
        if 'attachments' in data:
            ticket = self._create_ticket_with_attachment(url, data)
            return Ticket(**ticket)

        ticket = self._api._post(url, data=json.dumps(data))['ticket']
        return Ticket(**ticket)

    def _create_ticket_with_attachment(self, url, data):
        attachments = data['attachments']
        del data['attachments']
        multipart_data = []

        for attachment in attachments:
            file_name = attachment.split("/")[-1:][0]
            multipart_data.append(('attachments[]', (file_name, open(attachment, 'rb'), None)))

        for key, value in data.copy().items():
            # Reformat ticket properties to work with the multipart/form-data encoding.
            if isinstance(value, list) and not key.endswith('[]'):
                data[key + '[]'] = value
                del data[key]

        if 'custom_fields' in data and isinstance(data['custom_fields'], dict):
            # Reformat custom fields to work with the multipart/form-data encoding.
            for field, value in data['custom_fields'].items():
                data['custom_fields[{}]'.format(field)] = value
            del data['custom_fields']

        # Override the content type so that `requests` correctly sets it to multipart/form-data instead of JSON.
        ticket = self._api._post(url, data=data, files=multipart_data, headers={'Content-Type': None})['ticket']
        return ticket

    def create_outbound_email(self, subject, description, email, email_config_id, **kwargs):
        """Creates an outbound email"""
        url = 'tickets/outbound_email'
        priority = kwargs.get('priority', 1)
        data = {
            'subject': subject,
            'description': description,
            'priority': priority,
            'email': email,
            'email_config_id': email_config_id,
        }
        data.update(kwargs)
        ticket = self._api._post(url, data=json.dumps(data))['ticket']
        return Ticket(**ticket)

    def update_ticket(self, ticket_id, **kwargs):
        """Updates a ticket from a given ticket ID"""
        url = 'tickets/%d' % ticket_id
        ticket = self._api._put(url, data=json.dumps(kwargs))['ticket']
        return Ticket(**ticket)

    def delete_ticket(self, ticket_id):
        """Delete the ticket for the given ticket ID"""
        url = 'tickets/%d' % ticket_id
        self._api._delete(url)

    def list_tickets(self, max_pages=None, **kwargs):
        """List all tickets, optionally filtered by a view. Specify filters as
        keyword arguments, such as:

        filter_name = one of ['new_and_my_open', 'watching', 'spam', 'deleted',
                              None]
            (defaults to 'new_and_my_open')
            Passing None means that no named filter will be passed to
            Freshservice, which mimics the behavior of the 'all_tickets' filter
            in v1 of the API.

        Multiple filters are AND'd together.
        """

        filter_name = 'new_and_my_open'
        if 'filter_name' in kwargs:
            filter_name = kwargs['filter_name']
            del kwargs['filter_name']

        url = 'tickets'
        if filter_name is not None:
            url += '?filter=%s&' % filter_name
        else:
            url += '?'
        page = 1 if not 'page' in kwargs else kwargs['page']
        per_page = 100 if not 'per_page' in kwargs else kwargs['per_page']
        tickets = []

        # Skip pagination by looping over each page and adding tickets if 'page' key is not in kwargs.
        # else return the requested page and break the loop
        while True:
            this_page = self._api._get(url + 'page=%d&per_page=%d'
                                       % (page, per_page), kwargs)['tickets']
            tickets += this_page
            if len(this_page) < per_page or 'page' in kwargs or (max_pages is not None and page >= max_pages):
                break
            page += 1

        all_selected_tickets=[]
        # Currently we force update cache for all these tickets
        # TODO: if self._api.updatecache is false, pull all from cache (need
        #   to locally implement filters / views)
        for ticket in tickets:
            _ticketcachefile = self.id_to_cache_path(ticket['id'])
            new_ticketcachefile = not _ticketcachefile.exists()
            with open(_ticketcachefile, mode='wb') as f:
                pickle.dump(ticket,f)
            all_selected_tickets.append(Ticket(**ticket))
            if new_ticketcachefile:
                os.chmod(_ticketcachefile, self._api.cachemode)
                if self._api.cachegroup:
                    shutil.chown(_ticketcachefile, group=self._api.cachegroup)

        return all_selected_tickets

    def list_new_and_my_open_tickets(self):
        """List all new and open tickets."""
        return self.list_tickets(filter_name='new_and_my_open')

    def list_watched_tickets(self):
        """List watched tickets, closed or open."""
        return self.list_tickets(filter_name='watching')

    def list_deleted_tickets(self):
        """Lists all deleted tickets."""
        return self.list_tickets(filter_name='deleted')

    def summarize_ticket(self, ticket, verbosity=0):
        if ticket is None:
            if verbosity > 2:
                print("summarize_ticket was passed an empty ticket object")
            return
        if ticket.responder_id is None:
            agent = "Unassigned"
        else:
            agent = self._api.agents.get_agent(ticket.responder_id)
        print(
            f'Ticket #{ticket.id} -> {self._api._gui_prefix}tickets/{ticket.id}\n'
            ,end="")
        if hasattr(ticket, 'related_tickets') and verbosity > 0:
            related = ticket.related_tickets
            if 'child_ids' in related:
                for child_id in related['child_ids']:
                    print(f"\tChild ticket #{child_id}")
            if 'parent_id' in related:
                print(f"\tParent ticket #{related['parent_id']}")
        if verbosity > 0:
            print(
                f'\tSubject: {ticket.subject}\n'
                f'\tRequester: {self._api.requesters.requester(ticket.requester_id)}\n'
                f'\tCreated at: {ticket.created_at}\n'
                ,end="")
        if verbosity > 2:
            print(
                f'\tUpdated at: {ticket.updated_at}\n'
                f'\tSource: {ticket.source}\n'
                f'\tTo_Emails: {ticket.to_emails}\n'
                f'\tCC_Emails: {ticket.cc_emails}\n'
                ,end="")
        if verbosity > 1:
            print(
                f'\tGroup: {self._api.groups.get_group(ticket.group_id)}\n'
                f'\tStatus: {ticket.status}\n'
                f'\tAgent: {agent}\n'
                ,end="")
        if verbosity > 2:
            print(
                f'\tDue by: {ticket.due_by}\n'
                f'\tDeleted: {ticket.deleted}\n'
                ,end="")
        # always print this lengthy field at the end of the output
        tw.max_lines = 5 if verbosity < 3 else None
        if verbosity > 1:
            print(f'\tDescription:')
            print(tw.fill(ticket.description_text))

class ConversationAPI(object):
    def __init__(self, api):
        self._api = api

    def list_conversations(self, ticket_id):
        url = 'tickets/%d/conversations' % ticket_id
        conversations = []
        for c in self._api._get(url)['conversations']:
            conversations.append(Conversation(**c))
        return conversations

    def create_note(self, ticket_id, body, **kwargs):
        url = 'tickets/%d/notes' % ticket_id
        data = {'body': body}
        data.update(kwargs)
        return Conversation(**self._api._post(url, data=json.dumps(data))['conversation'])

    def create_reply(self, ticket_id, body, **kwargs):
        url = 'tickets/%d/reply' % ticket_id
        data = {'body': body}
        data.update(kwargs)
        return Conversation(**self._api._post(url, data=json.dumps(data))['conversation'])


class GroupAPI(object):

    def __init__(self, api):
        self._api = api
        self._cachefile = Path(self._api.cachedir, "groups")
        self.all_groups = None
        new_cachefile = not self._cachefile.exists()
        if new_cachefile or any(x in ['groups', 'all'] for x in self._api.updatecache):
            self.all_groups = self.list_groups()
            with open(self._cachefile, mode='wb') as f:
                pickle.dump(self.all_groups,f)
            if new_cachefile:
                os.chmod(self._cachefile, self._api.cachemode)
                if self._api.cachegroup:
                    shutil.chown(self._cachefile, group=self._api.cachegroup)
        else:
            with open(self._cachefile, mode='rb') as f:
                self.all_groups = pickle.load(f)

    def list_groups(self, **kwargs):
        url = 'groups?'
        page = 1 if not 'page' in kwargs else kwargs['page']
        per_page = 100 if not 'per_page' in kwargs else kwargs['per_page']

        groups = []
        while True:
            this_page = self._api._get(url + 'page=%d&per_page=%d'
                                       % (page, per_page), kwargs)['groups']
            groups += this_page
            if len(this_page) < per_page or 'page' in kwargs:
                break
            page += 1

        return [Group(**g) for g in groups]

    def get_groupid(self, name):
        return next((group.id for group in self.all_groups if group.name == name), None)

    def match_group(self, keyword):
        """Find all groups whose name matches keyword"""
        return [group for group in self.all_groups if 
            keyword.lower() in group.name.lower()]

    def get_group(self, id):
        """Fetches the group for the given group ID"""
        return next((group for group in self.all_groups if group.id == id), None)
        #url = 'groups/%s' % id
        #return Group(**self._api._get(url)['group'])


class RoleAPI(object):
    def __init__(self, api):
        self._api = api

    def list_roles(self):
        url = 'roles'
        roles = []
        for r in self._api._get(url)['roles']:
            roles.append(Role(**r))
        return roles

    def get_role(self, role_id):
        url = 'roles/%s' % role_id
        return Role(**self._api._get(url)['roles'])


class TicketFieldAPI(object):
    def __init__(self, api):
        self._api = api

    def list_ticket_fields(self, **kwargs):
        url = 'ticket_fields'
        ticket_fields = []

        if 'type' in kwargs:
            url = "{}?type={}".format(url, kwargs['type'])

        for tf in self._api._get(url)['ticket_fields']:
            ticket_fields.append(TicketField(**tf))
        return ticket_fields


class AgentAPI(object):

    def __init__(self, api):
        self._api = api
        self._cachefile = Path(self._api.cachedir, "agents")
        self.all_agents = None
        new_cachefile = not self._cachefile.exists()
        if new_cachefile or any(x in ['agents', 'all'] for x in self._api.updatecache):
            self.all_agents = self.list_agents()
            with open(self._cachefile, mode='wb') as f:
                pickle.dump(self.all_agents,f)
            if new_cachefile:
                os.chmod(self._cachefile, self._api.cachemode)
                if self._api.cachegroup:
                    shutil.chown(self._cachefile, group=self._api.cachegroup)
        else:
            with open(self._cachefile, mode='rb') as f:
                self.all_agents = pickle.load(f)

    def list_agents(self, **kwargs):
        """List all agents, optionally filtered by a view. Specify filters as
        keyword arguments, such as:

        {
            email='abc@xyz.com',
            phone=873902,
            mobile=56523,
            state='fulltime'
        }

        Passing None means that no named filter will be passed to
        Freshservice, which returns list of all agents

        Multiple filters are AND'd together.
        """

        url = 'agents?'
        page = 1 if not 'page' in kwargs else kwargs['page']
        per_page = 100 if not 'per_page' in kwargs else kwargs['per_page']

        agents = []

        # Skip pagination by looping over each page and adding tickets if 'page' key is not in kwargs.
        # else return the requested page and break the loop
        while True:
            this_page = self._api._get(url + 'page=%d&per_page=%d'
                                       % (page, per_page), kwargs)['agents']
            agents += this_page
            if len(this_page) < per_page or 'page' in kwargs:
                break
            page += 1

        return [Agent(**a) for a in agents]

    def match_agent(self, keyword):
        """Find all agents whose first_name, last_name, or email match keyword"""
        return [agent for agent in self.all_agents if any(
            [keyword.lower() in field.lower() for field in [agent.first_name, agent.last_name, agent.email]]
            )]

    def get_agent(self, id):
        """Fetches the agent for the given agent ID"""
        return next((agent for agent in self.all_agents if agent.id == id), None)
        #url = 'agents/%s' % agent_id
        #return Agent(**self._api._get(url)['agent'])

    def update_agent(self, agent_id, **kwargs):
        """Updates an agent"""
        url = 'agents/%s' % agent_id
        agent = self._api._put(url, data=json.dumps(kwargs))['agent']
        # TODO: update all_agents and cache
        #with open(cachefile, mode='wb') as f:
        #    pickle.dump(self.all_agents,f)
        return Agent(**agent)

    def delete_agent(self, agent_id):
        """Delete the agent for the given agent ID"""
        url = 'agents/%d' % agent_id
        self._api._delete(url)

    def currently_authenticated_agent(self):
        """Fetches currently logged in agent"""
        url = 'agents/me'
        return Agent(**self._api._get(url)['agent'])

class RequesterAPI(object):

    def __init__(self, api):
        self._api = api
        self._cachefile = Path(self._api.cachedir, "requesters")
        self.all_requesters = None
        new_cachefile = not self._cachefile.exists()
        if new_cachefile or any(x in ['requesters', 'all'] for x in self._api.updatecache):
            self.all_requesters = self.list_requesters()
            with open(self._cachefile, mode='wb') as f:
                pickle.dump(self.all_requesters,f)
            if new_cachefile:
                os.chmod(self._cachefile, self._api.cachemode)
                if self._api.cachegroup:
                    shutil.chown(self._cachefile, group=self._api.cachegroup)
        else:
            with open(self._cachefile, mode='rb') as f:
                self.all_requesters = pickle.load(f)

    def list_requesters(self, **kwargs):
        """List all requesters, optionally filtered by a view. Specify filters as
        keyword arguments, such as:

        {
            email='abc@xyz.com',
            phone=873902,
            mobile=56523,
            state='fulltime'
        }

        Passing None means that no named filter will be passed to
        Freshservice, which returns list of all requesters

        Multiple filters are AND'd together.
        """

        url = 'requesters?'
        page = 1 if not 'page' in kwargs else kwargs['page']
        per_page = 100 if not 'per_page' in kwargs else kwargs['per_page']

        requesters = []

        # Skip pagination by looping over each page and adding tickets if 'page' key is not in kwargs.
        # else return the requested page and break the loop
        while True:
            this_page = self._api._get(url + 'page=%d&per_page=%d'
                                       % (page, per_page), kwargs)['requesters']
            requesters += this_page
            if len(this_page) < per_page or 'page' in kwargs:
                break
            page += 1

        return [Requester(**r) for r in requesters]

    def requester(self, id):
        return next((requester for requester in self.all_requesters if requester.id == id), None)

    def requester_ids(self, email):
        return [requester.id for requester in self.all_requesters if email in requester.primary_email]

    def match_requester(self, keyword):
        """Find all requesters whose first_name, last_name, or primary email match keyword"""
        return [requester for requester in self.all_requesters if any(
            [keyword.lower() in field.lower() for field in [requester.first_name, requester.last_name, requester.primary_email]]
            )]

    def get_requester(self, id):
        """Fetches the requester for the given requester ID"""
        return next((requester for requester in self.all_requesters if requester.id == id), None)
        #url = 'requesters/%s' % id
        #return Requester(**self._api._get(url)['requester'])

    def update_requester(self, requester_id, **kwargs):
        """Updates a requester"""
        url = 'requesters/%s' % requester_id
        requester = self._api._put(url, data=json.dumps(kwargs))['requester']
        return Requester(**requester)

    def delete_requester(self, requester_id):
        """Delete the requester for the given requester ID"""
        url = 'requesters/%d' % requester_id
        self._api._delete(url)


class API(object):

    def __init__(self, domain, api_key, verify=True, proxies=None, cachedir=None, updatecache=[]):
        """Creates a wrapper to perform API actions.

        Arguments:
          domain:    the Freshservice domain (not custom). e.g. company.freshservice.com
          api_key:   the API key

        Instances:
          .tickets:  the Ticket API
        """

        self._api_prefix = 'https://{}/api/v2/'.format(domain.rstrip('/'))
        self._gui_prefix = 'https://{}/helpdesk/'.format(domain.rstrip('/'))
        self._session = requests.Session()
        self._session.auth = (api_key, 'unused_with_api_key')
        self._session.verify = verify
        self._session.proxies = proxies
        self._session.headers = {'Content-Type': 'application/json'}

        self.updatecache = updatecache
        # priority order: cachedir parameter, FRESHSERVICE_CACHEDIR, home directory
        if cachedir is not None:
            self.cachedir = Path(cachedir)
        else:
            self.cachedir = Path(os.environ.get('FRESHSERVICE_CACHEDIR', Path(Path.home(),".cache","freshservice")))
        self.cachemode = int(os.environ.get('FRESHSERVICE_CACHEMODE', '0o600'),base=0)
        self.cachegroup = os.environ.get('FRESHSERVICE_CACHEGROUP')
        self.cachedirmode = int(os.environ.get('FRESHSERVICE_CACHEDIRMODE', '0o700'),base=0)
        if not self.cachedir.exists():
            try:
                os.mkdir(self.cachedir)
                os.chmod(self.cachedir, self.cachedirmode)
            except:
                raise AttributeError(f'Cannot create cache directory {self.cachedir}')
            if self.cachegroup:
                shutil.chown(self.cachedir, group=self.cachegroup)
        self.apiusagefile=Path(self.cachedir, "apiusage")
        self.apiusagehistoryfile=Path(self.cachedir, "apiusage.history")
        self.new_apiusagefile=not self.apiusagefile.exists()
        self.new_apiusagehistoryfile=not self.apiusagehistoryfile.exists()

        self.tickets = TicketAPI(self)
        self.conversations = ConversationAPI(self)
        self.groups = GroupAPI(self)
        self.agents = AgentAPI(self)
        self.requesters = RequesterAPI(self)
        self.roles = RoleAPI(self)
        self.ticket_fields = TicketFieldAPI(self)

        if domain.find('freshservice.com') < 0:
            raise AttributeError('Freshservice v2 API works only via Freshservice'
                                 'domains and not via custom CNAMEs')
        self.domain = domain

        # dummy initial values to show they are not yet properly initialized via API call
        #   but integers will allow testing with simple integer expressions
        if self.new_apiusagefile:
            self.ratelimit_remaining = 9999999999
            self.ratelimit_total     = 9999999999
            self.ratelimit_used      = 9999999999
        else:
            with open(self.apiusagefile, mode='r') as f:
                (self.ratelimit_remaining, self.ratelimit_total, self.ratelimit_used) = tuple(map(int, f.readlines()))


    def _action(self, req, url):

        try:
            j = req.json()
        except ValueError:
            j = {}

        error_message = 'Freshservice Request Failed'
        if 'errors' in j:
            error_message = '{}: {}'.format(j.get('description'), j.get('errors'))
        elif 'message' in j:
            error_message = j['message']
            
        if req.status_code == 400:
            raise FreshserviceBadRequest(error_message)
        elif req.status_code == 401:
            raise FreshserviceUnauthorized(error_message)
        elif req.status_code == 403:
            raise FreshserviceAccessDenied(error_message)
        elif req.status_code == 404:
            raise FreshserviceNotFound(error_message)
        elif req.status_code == 429:
            raise FreshserviceRateLimited(
                '429 Rate Limit Exceeded: API rate-limit has been reached until {} seconds. See '
                'http://freshservice.com/api#ratelimit'.format(req.headers.get('Retry-After')))
        elif 500 < req.status_code < 600:
            raise FreshserviceServerError('{}: Server Error'.format(req.status_code))

        # Catch any other errors
        try:
            req.raise_for_status()
        except HTTPError as e:
            raise FreshserviceError("{}: {}".format(e, j))

        self.ratelimit_remaining = req.headers['x-ratelimit-remaining']
        self.ratelimit_total = req.headers['x-ratelimit-total']
        self.ratelimit_used = req.headers['x-ratelimit-used-currentrequest']

        with open(self.apiusagefile, mode='w') as f:
            f.write(f"{self.ratelimit_remaining}\n")
            f.write(f"{self.ratelimit_total}\n")
            f.write(f"{self.ratelimit_used}\n")
        with open(self.apiusagehistoryfile, mode='a') as f:
            f.write(f'{datetime.today().strftime("%Y%m%d_%H%M")} {self.ratelimit_remaining} {getpass.getuser()} {url}\n')
        if self.new_apiusagefile:
            os.chmod(self.apiusagefile, self.cachemode)
            if self.cachegroup:
                shutil.chown(self.apiusagefile, group=self.cachegroup)
        if self.new_apiusagehistoryfile:
            os.chmod(self.apiusagehistoryfile, self.cachemode)
            if self.cachegroup:
                shutil.chown(self.apiusagehistoryfile, group=self.cachegroup)

        return j

    def _get(self, url, params={}):
        """Wrapper around request.get() to use the API prefix. Returns a JSON response."""
        req = self._session.get(self._api_prefix + url, params=params)
        return self._action(req, url)

    def _post(self, url, data={}, **kwargs):
        """Wrapper around request.post() to use the API prefix. Returns a JSON response."""
        req = self._session.post(self._api_prefix + url, data=data, **kwargs)
        return self._action(req, url)

    def _put(self, url, data={}):
        """Wrapper around request.put() to use the API prefix. Returns a JSON response."""
        req = self._session.put(self._api_prefix + url, data=data)
        return self._action(req, url)

    def _delete(self, url):
        """Wrapper around request.delete() to use the API prefix. Returns a JSON response."""
        req = self._session.delete(self._api_prefix + url)
        return self._action(req, url)

def age_to_utc(**kwargs):
    return (datetime.today() - timedelta(**kwargs)).isoformat()
