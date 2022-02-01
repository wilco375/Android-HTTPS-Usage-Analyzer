def add_or_set(dictionary, key, value=1):
    """
    Add value to a value in a dictionary, set it if the key doesn't exist.
    :param dictionary: dictionary
    :type dictionary: dict
    :param key: dictionary key
    :type key: str
    :param value: value to set or add
    :type value: int
    :return:
    """
    if key in dictionary:
        dictionary[key] += value
    else:
        dictionary[key] = value
