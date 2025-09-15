# -*- coding: utf-8 -*-
{
    'name': "Base ACT",

    'summary': "Cross module logic",

    'description': """
        ACT logic for multiple module
        =======================================

        This module provides tools needed by two or more modules among the list of modules

        Features:
        - LDAP connection
        - CRON jobs
    """,

    'author': "Pierre Dramaix",
    'website': "https://www.autocontrole.be",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/15.0/odoo/addons/base/data/ir_module_category_data.xml
    # for the full list
    'category': 'Technical',
    'version': '0.1',


    'depends': ['base', 'web', 'auth_signup'],
    'assets': {
        'web.assets_frontend': [
            'base_act/static/src/scss/login.scss',
        ],
        'web.assets_backend': [
            'base_act/static/src/scss/navbar.scss',
            'base_act/static/src/js/user_info_systray.js',
            'base_act/static/src/xml/user_info_systray.xml',
            'base_act/static/src/scss/user_info_systray.scss',
        ],
    },

    # always loaded
    'data': [
        # Security
        'security/ir.model.access.csv',

        # Data
        'data/ir_cron.xml',

        # views
        'views/login_templates.xml',
        'views/custom_systray_views.xml',
        'views/web_favicon.xml',


    ],




    'demo': [],
    'installable': True,
    'application': False,
    'auto_install': True,
    'license': 'LGPL-3',
}

