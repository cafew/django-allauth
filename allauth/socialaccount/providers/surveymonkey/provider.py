from allauth.socialaccount import providers
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider

from allauth.socialaccount.app_settings import QUERY_EMAIL


class Scope(object):
    EMAIL = 'email'
    PROFILE = 'profile'


class SurveyMonkeyOAuth2Account(ProviderAccount):
    pass


class SurveyMonkey2Provider(OAuth2Provider):
    id = 'surveymonkey'
    name = 'SurveyMonkey'
    account_class = SurveyMonkeyOAuth2Account

    def get_default_scope(self):
        scope = [Scope.PROFILE]
        if QUERY_EMAIL:
            scope.append(Scope.EMAIL)
        return scope

    def get_auth_params(self, request, action):
        ret = super(SurveyMonkey2Provider, self).get_auth_params(request, action)
        app = self.get_app(request)
        # app = provider.get_app(self.request) where self <-> OAuth2LoginView
        # is self.request the same as request ?
        if app.key:  # API key
            ret['api_key'] = app.key
        return ret

    def extract_uid(self, data):
        return data['user_details']["user_id"]

    def extract_common_fields(self, data):
        return dict(data["user_details"])


providers.registry.register(SurveyMonkey2Provider)
