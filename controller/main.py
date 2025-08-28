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

                elif len(matching_users) > 1:
                    # Multiple users found - show selection
                    users_list = []
                    for dn, attrs in matching_users:
                        display_name = attrs.get('displayName', [b''])[0]
                        if isinstance(display_name, bytes):
                            display_name = display_name.decode('utf-8')

                        login = attrs.get('SamAccountName', [b''])[0]
                        if isinstance(login, bytes):
                            login = login.decode('utf-8')

                        users_list.append({
                            'login': login,
                            'display_name': display_name or login
                        })

                    # Store in session
                    request.session['tag_users'] = users_list
                    request.session['tag_number'] = tag_number
                    request.session['redirect'] = redirect

                    # Use a simpler rendering approach
                    response = request.make_response(request.env['ir.ui.view']._render_template(
                        'base_act.select_user',
                        {
                            'tag_users': users_list,
                            'csrf_token': request.csrf_token(),
                        }
                    ))
                    return response

                else:
                    # No user found
                    values = request.params.copy()
                    values['error'] = _("No user found with this tag number")
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

            if not user:
                _logger.info("Creating new user from LDAP")
                company = request.env.company or request.env['res.company'].sudo().search([], limit=1)
                user_id = users.with_company(company)._sync_ldap_user(ldap_attrs, login)
                if not user_id:
                    raise ValueError("Failed to create user")
                user = users.browse(user_id)
            else:
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
                    'password': False,
                    'is_ldap_user': True,
                })
                request.env.cr.commit()
                _logger.info("Restored user settings")

                return request.redirect(redirect or '/web')

            raise ValueError("Authentication failed")

        except Exception as e:
            _logger.error(f"Tag login error: {e}")
            _logger.error(f"Error type: {type(e)}")
            import traceback
            _logger.error(f"Full traceback: {traceback.format_exc()}")
            request.env.cr.rollback()
            values = request.params.copy()
            values['error'] = _("Authentication failed: Unable to create or access user account")
            return request.render('web.login', values)