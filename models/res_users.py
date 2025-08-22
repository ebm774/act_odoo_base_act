# -*- coding: utf-8 -*-
from odoo import models

class ResUsers(models.Model):
    """Extend res.users to include LDAP authentication"""
    _name = 'res.users'
    _inherit = ['res.users', 'base_act.ldap.users']