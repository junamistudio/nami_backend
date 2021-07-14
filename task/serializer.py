import json
from datetime import datetime
from time import mktime


class CeleryEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return {
                '__type__': '__datetime__',
                'epoch': int(mktime(obj.timetuple()))
            }
        else:
            return json.JSONEncoder.default(self, obj)


def my_decoder(obj):
    if '__type__' in obj:
        if obj['__type__'] == '__datetime__':
            return datetime.fromtimestamp(obj['epoch'])
    return obj


# Encoder function
def celery_dumps(obj):
    return json.dumps(obj, cls=CeleryEncoder)


# Decoder function
def celery_loads(obj):
    return json.loads(obj, object_hook=CeleryEncoder)
