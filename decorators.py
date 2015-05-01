

def restrict_to_ip_in_list(ip_list):
    def wrapper(view_func):
        def wrapped_view(*args, **kwargs):
            return view_func(*args, **kwargs)
        wrapped_view.whitelist_ips = ip_list
        return wrapped_view
    return wrapper