from django.conf import settings

def get_client_ip(request):
	return {'clientIP': request.META['REMOTE_ADDR']}