""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import _run_operation, _check_health

logger = get_logger('cybereason-threat-intel')


class CybereasonTI(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            params.update({"operation": operation})
            return _run_operation(config, params)
        except Exception as err:
            logger.error('CybereasonTI:{}'.format(err))
            raise ConnectorError('CybereasonTI:{}'.format(err))

    def check_health(self, config):
        return _check_health(config)
