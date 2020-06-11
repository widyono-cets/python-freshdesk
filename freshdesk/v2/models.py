import dateutil.parser


class FreshdeskModel(object):
    _keys = None

    def __init__(self, **kwargs):
        self._keys = set()

        if "custom_field" in kwargs.keys() and len(kwargs["custom_field"]) > 0:
            custom_fields = kwargs.pop("custom_field")
            kwargs.update(custom_fields)
        for k, v in kwargs.items():
            if hasattr(Ticket, k):
                k = '_' + k
            # testing: all null e-mail values should be converted to empty string
            #   to speed up searchability
            if "email" in k:
                if v is None:
                    v=''
            setattr(self, k, v)
            self._keys.add(k)
        if hasattr(self, 'created_at') and self.created_at:
            self.created_at = self._to_timestamp(self.created_at)
        if hasattr(self, 'updated_at') and self.updated_at:
            self.updated_at = self._to_timestamp(self.updated_at)
        if hasattr(self, 'last_login_at') and self.last_login_at:
            self.last_login_at = self._to_timestamp(self.last_login_at)

    def _to_timestamp(self, timestamp_str):
        """Converts a timestamp string as returned by the API to
        a native datetime object and return it."""
        return dateutil.parser.parse(timestamp_str)


class TicketField(FreshdeskModel):
    def __str__(self):
        return self.name

    def __repr__(self):
        return '<TicketField \'{}\' \'{}\'>'.format(self.name, self.description)

class Ticket(FreshdeskModel):

    # https://api.freshservice.com/v2/#update_ticket_priority
    statuses = [
        None,
        None,
        'Open',            # 2
        'Pending',         # 3
        'Resolved',        # 4
        'Closed'           # 5
    ]
    priorities = [
        None,
        'Low',             # 1
        'Medium',          # 2
        'High',            # 3
        'Urgent'           # 4
    ]
    sources = [
        None,
        'Email',           # 1
        'Portal',          # 2
        'Phone',           # 3
        'Chat',            # 4
        'Feedback Widget', # 5
        'Yammer',          # 6
        'AWS Cloudwatch',  # 7
        'Pagerduty',       # 8
        'Walkup',          # 9
        'Slack'            # 10
        ]

    def __str__(self):
        return self.subject

    def __repr__(self):
        return '<Ticket #INC-{} \'{}\'>'.format(self.id, self.subject)

    @property
    def priority(self):
        try:
            return self.priorities[self._priority]
        except KeyError:
            return 'priority_{}'.format(self._priority)

    @property
    def status(self):
        try:
            return self.statuses[self._status]
        except KeyError:
            return 'status_{}'.format(self._status)

    @property
    def source(self):
        try:
            return self.sources[self._source]
        except KeyError:
            return 'source_{}'.format(self._source)

class Group(FreshdeskModel):
    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Group \'{}\' -> {}>'.format(self.name, self.id)


class Comment(FreshdeskModel):
    def __str__(self):
        return self.body_text

    def __repr__(self):
        return '<Comment for Ticket #{}>'.format(self.ticket_id)

    @property
    def source(self):
        _s = {0: 'reply', 2: 'note', 5: 'twitter', 6: 'survey', 7: 'facebook',
              8: 'email', 9: 'phone', 10: 'mobihelp', 11: 'e-commerce'}
        return _s[self._source]


class Agent(FreshdeskModel):
    def __str__(self):
        return '{} {}'.format(self.first_name, self.last_name)

    def __repr__(self):
        return '<Agent #{} \'{} {}\'>'.format(self.id, self.first_name, self.last_name)

class Requester(FreshdeskModel):
    def __str__(self):
        return '{} {}'.format(self.first_name, self.last_name)

    def __repr__(self):
        return '<Requester #{} \'{} {}\'>'.format(self.id, self.first_name, self.last_name)

class Role(FreshdeskModel):
    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Role \'{}\'>'.format(self.name)    

