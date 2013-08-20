from dateutil.tz import tzoffset


class FixedOffsetTimezone(tzoffset):
    def __init__(self, offset=None, name=None):
        super(FixedOffsetTimezone, self).__init__(name, offset)
