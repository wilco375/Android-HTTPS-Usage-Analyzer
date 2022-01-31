def retry(function, retries=3):
    """
    Try to execute function, if it returns False, retry up to retries times
    :param function: function to execute
    :type function: function
    :param retries: number of retries
    :type retries: int
    :return: False if function failed, result of function otherwise
    """
    for i in range(retries):
        result = function()
        if result is not False:
            return result
    return False