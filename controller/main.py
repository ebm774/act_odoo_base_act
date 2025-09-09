# -*- coding: utf-8 -*-

from odoo import http, _, fields, api
from odoo.http import request
from odoo.addons.web.controllers.home import Home
import datetime
import json
import logging
import secrets


_logger = logging.getLogger(__name__)


class LoginController(Home):

    @http.route('/web/login', type='http', auth="none", website=True, sitemap=False)
    def web_login(self, redirect=None, **kw):
        """Override login to add tag authentication option"""

        # Handle tag authentication if submitted
        if request.httprequest.method == 'POST' and kw.get('auth_method') == 'tag':
            tag_number = kw.get('tag_number', '').strip()

            if tag_number and tag_number.isdigit():
                # Search for users with this tag
                connector = request.env['base_act.ldap.connector'].sudo()
                matching_users = connector.search_users_by_tag(tag_number)


                if len(matching_users) == 1:
                    # Single user found - authenticate directly
                    dn, attrs = matching_users[0]

                    login = attrs.get('sAMAccountName', [b''])[0].decode('utf-8')
                    # Auto-login with tag (create session without password)
                    return self._process_tag_login(login, attrs, redirect)

                else:
                    # No user or more than one user found
                    values = request.params.copy()
                    values['error'] = _(
                        "Invalid tag number or authentication system temporarily unavailable. Please try again or use password login.")
                    return request.render('web.login', values)

        # Handle user selection from multiple accounts
        if request.httprequest.method == 'POST' and kw.get('selected_user'):
            selected_login = kw.get('selected_user')
            redirect = request.session.get('redirect')

            # Get user data and process login
            connector = request.env['base_act.ldap.connector'].sudo()
            user_data = connector.search_user(selected_login)

            if user_data:
                dn, attrs = user_data
                return self._process_tag_login(selected_login, attrs, redirect)

        # Default login page with auth method selector
        response = super().web_login(redirect, **kw)

        return response

    def _process_tag_login(self, login, ldap_attrs, redirect=None):
        """Process login for tag-authenticated user"""
        _logger.info("_process_tag_login")
        try:
            # Create or get user
            users = request.env['res.users'].sudo()
            user = users.search([('login', '=', login)], limit=1)
            _logger.info(f"login : {login}")

            if user :
                _logger.info("Updating existing user")
                user._sync_ldap_user(ldap_attrs, login)

                request.env.cr.commit()
                _logger.info("User sync completed")

                # Generate temporary password and temporarily disable LDAP
                temp_password = secrets.token_urlsafe(32)
                _logger.info("Generated temp password")

                user.sudo().write({
                    'password': temp_password,
                    'is_ldap_user': False,
                })
                _logger.info("Updated user with temp password")
                request.env.cr.commit()
                _logger.info("Committed temp password")


                # Authenticate normally (server-side API expects positional args)
                _logger.info("About to call session.authenticate")
                _logger.info("db name is : %s", request.db)

                credential = {
                    'type': 'password',  # required by Odoo
                    'login': login,  # the user login you found
                    'password': temp_password,  # placeholder; won’t be used if you short-circuit
                }

                uid = request.session.authenticate(request.db, credential)
                _logger.info(f"Authentication returned: {uid}")

                if uid:
                    _logger.info("Authentication successful via temp password")
                    # Re-enable LDAP and clear password
                    user.sudo().write({
                        'password': '',
                        'is_ldap_user': True,
                    })
                    request.env.cr.commit()
                    _logger.info("Restored user settings")

                    return request.redirect(redirect or '/web')


        except Exception as e:
            request.env.cr.rollback()
            values = request.params.copy()
            values['error'] = _("Authentication failed: Unable to create or access user account")
            return request.render('web.login', values)