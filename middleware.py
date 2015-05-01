from django.http.response import HttpResponse
from ip_utils import util


class IPRestrictionMiddleware(object):
    def process_view(self, request, view_func, args, kwargs):
        if hasattr(view_func, 'whitelist_ips'):
            if not util.check_ip_is_authorized(request.META['REMOTE_ADDR'], view_func.whitelist_ips):
                return HttpResponse('Unauthorized', status=401)
        return None
