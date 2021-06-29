""" Connector """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health
logger = get_logger('cybereason')


class CybereasonTI(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            params.update({"operation":operation})              
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.error('CybereasonTI:{}'.format(err))
            raise ConnectorError('CybereasonTI:{}'.format(err))


    def check_health(self, config):
        return _check_health(config)