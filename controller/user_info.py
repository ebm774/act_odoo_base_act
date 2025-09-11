# -*- coding: utf-8 -*-

from odoo import http
from odoo.http import request
import json

class UserInfoController(http.Controller):

    @http.route('/web/user_info', type='json', auth='user')
    def get_user_info(self):
        """Get current user info including department"""
        user = request.env.user
        return {
            'name': user.name,
            'login': user.login,
            'department_id': user.department_id.id if user.department_id else False,
            'department_name': user.department_id.name if user.department_id else 'No Department'
        }