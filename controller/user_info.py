# -*- coding: utf-8 -*-

from odoo import http
from odoo.http import request
import json

class UserInfoController(http.Controller):

    @http.route('/web/user_info', type='json', auth='user')
    def get_user_info(self):
        """Get current user info including department"""
        user = request.env.user

        # Get all departments
        departments = user.department_ids
        primary_dept = departments[0] if departments else None

        return {
            'name': user.name,
            'login': user.login,

            # New Many2many fields
            'department_ids': departments.ids,
            'department_names': departments.mapped('name'),
            'departments': [{'id': d.id, 'name': d.name} for d in departments],

            # Backward compatibility (using primary/first department)
            'department_id': primary_dept.id if primary_dept else False,
            'department_name': primary_dept.name if primary_dept else 'No Department'
        }