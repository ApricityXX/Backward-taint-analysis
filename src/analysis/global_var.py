def _init():
    global _global_dict
    _global_dict = {}
    _global_dict['need_agrs'] = False
    _global_dict['is_local_function'] = False


def set_value(key, value):
    _global_dict[key] = value


def get_value(key):
    try:
        return _global_dict[key]
    except:
        pass
