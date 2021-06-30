""" Operations """
from .utils import *
from connectors.core.connector import get_logger, ConnectorError

import requests
import logging

logger = get_logger('Cybereason-Threat-Intel')
logger.setLevel(logging.DEBUG)# Comment for prod

class CybereasonTIMC(object):
    def __init__(self, config):
        self.url_ti = config.get('threat_intel_server').strip()
        if not self.url_ti.startswith('https://'):
            self.url_ti = 'https://' + self.url_ti
        if self.url_ti[-1] == '/':
            self.url_ti = self.url_ti[:-1]

        self.url_auth = config.get('server').strip()
        if not self.url_auth.startswith('https://'):
            self.url_auth = 'https://' + self.url_auth
        if self.url_auth[-1] == '/':
            self.url_auth = self.url_auth[:-1]
        self.username = config['username']
        self.password = config['password']        
        self.verify_ssl = config['verify_ssl']
        self.headers = {
            'Content-Type': 'application/json',
            'Connection': 'close'
        }
        self.session = requests.session()
        self.login()


    def close(self):
        '''
        Closes the session before exit
        '''
        return self.make_rest_call(endpoint='/logout',method='GET')


    def login(self):
        '''
        Credentials login
        #TODO: implement certificate based authentication
        '''
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'close'
        }
        data = {
            'username': self.username,
            'password': self.password
        }
        return self.make_rest_call(endpoint='/login.html', data=data, headers=headers)


    def make_rest_call(self, endpoint, json=None,data=None,headers=None,params=None,method='POST'):
        '''
        Requests wrapper
        '''
        url = self.url_auth if '/log' in endpoint else self.url_ti
        try:
            response = self.session.request(method,
                                            url=url + endpoint,
                                            headers=headers or self.headers,
                                            json=json,
                                            data=data,
                                            params=params,
                                            #proxies={'https':'http://127.0.0.1:8080'}, # debug requests via mitmproxy
                                            verify=self.verify_ssl)

            if response.status_code in [200]:
                try:
                    response_data = response.json()
                    return {'status': response_data['status'] if 'status' in response_data else 'Success', 'data': response_data}
                except Exception as e:
                    response_data = response.content
                    return {'status':'Failure','data':response_data}

            else:
                raise ConnectorError({'status':'Failure','status_code':str(response.status_code),'response':response.content})

        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))


    def query_threat_intel(self,params):
        '''
        Returns details on a file’s reputation based on the Cybereason threat intelligence service
        test: 9e278e68b86e509c3ad62223f2fe1c1b
        test: 2400:cb00:2048:1::681b:9c87
        test: plxeyaja.com
        '''
        json_body = payload_builder(params)
        logger.debug('JSON Body: {}'.format(json_body))
        operation = params.get('operation')
        endpoint = '/rest/classification_v1/{}'.format(operation)
        return self.make_rest_call(endpoint=endpoint, json=json_body)


    def file_batch(self,params):
        '''
        Returns details on a file’s reputation based on the Cybereason threat intelligence service
        '''
        return self.query_threat_intel(params)


    def ip_batch(self,params):
        '''
        Returns details on IP address reputations based on the Cybereason threat intelligence service
        '''
        return self.query_threat_intel(params)


    def domain_batch(self,params):
        '''
        Returns details on domain reputations based on the Cybereason threat intelligence service
        '''
        return self.query_threat_intel(params)




def _run_operation(config,params):
    '''
    Map operations to CybereasonTI methods
    '''
    operation = params['operation']
    cr_object = CybereasonTIMC(config)
    command = getattr(CybereasonTIMC,operation)
    response = command(cr_object,params)
    cr_object.close()
    return response


def _check_health(config):
    '''
    Test service availability with a login/logoff
    '''
    try:
        cr_object = CybereasonTIMC(config)
        server_data = cr_object.make_rest_call(endpoint='/rest/download_v1/port', json={})
        cr_object.close()
        return server_data
        # if server_config['status'] == 'Failure':
        #     logger.exception('Authentication Error, Check URL and Credentials')
        #     raise ConnectorError('Authentication Error, Check URL and Credentials')

    except Exception as Err:
        logger.exception('Health Check Error:{}'.format(Err))
        raise ConnectorError('Health Check Error:{}'.format(Err))    
