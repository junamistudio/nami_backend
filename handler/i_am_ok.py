# -*- coding: utf-8 -*-
# Author: junami@126.com

import logging

from config import status
from handler import UserBaseHandler

logger = logging.getLogger()


class IamOK(UserBaseHandler):

    def get(self):
        """
        ---
        tags:
        - status
        summary: service status
        produces:
        - "application/json"
        responses:
            200:
                example: {
                }
        security:
        -   Token: []
        """
        msg = "I am OK"
        return self.out(status.success.code, msg=msg)
