from odoo import models, api, fields
import logging

_logger = logging.getLogger(__name__)


class LdapPermissionManager(models.TransientModel):
    _name = 'ldap.permission.manager'
    _description = 'LDAP Permission Manager'


    LDAP_GROUP_CONFIG = {
        'odoo_order_user': {
            'category': 'Order Management',
            'models': [
                'base_act.department',
                'mail.template',
                'mail.message',
                'ir.attachment'
            ],
            'permissions': {'read': True, 'write': True, 'create': False, 'unlink': False}
        },
        # Add new modules here - just add to this dict!
    }

    @api.model
    def setup_cross_module_permissions(self):
        """Called by CRON after LDAP user sync - gives users access to cross-module models"""
        _logger.info("Starting cross-module permissions setup...")

        for group_name, config in self.LDAP_GROUP_CONFIG.items():
            # Find the LDAP group
            group = self.env['res.groups'].search([('name', '=', group_name)], limit=1)
            if not group:
                _logger.warning(f"LDAP group not found: {group_name}")
                continue

            _logger.info(f"Processing cross-module permissions for group: {group_name}")

            # Get all users in this group
            group_users = group.users
            _logger.info(f"Found {len(group_users)} users in group {group_name}")

            # Create access rules for the configured models
            for model_name in config['models']:
                self._create_access_rule(group, model_name, config['permissions'])

        _logger.info("Cross-module permissions setup completed")

    def _create_access_rule(self, group, model_name, permissions):
        """Create access rule for a specific model and group"""

        # Find the model
        model = self.env['ir.model'].search([('model', '=', model_name)], limit=1)
        if not model:
            _logger.warning(f"Model not found: {model_name}")
            return

        # Create unique rule name
        rule_name = f"{model_name.replace('.', '_')}.{group.name}.cross_module"

        # Check if rule already exists
        existing = self.env['ir.model.access'].search([('name', '=', rule_name)], limit=1)

        rule_data = {
            'name': rule_name,
            'model_id': model.id,
            'group_id': group.id,
            'perm_read': permissions.get('read', False),
            'perm_write': permissions.get('write', False),
            'perm_create': permissions.get('create', False),
            'perm_unlink': permissions.get('unlink', False),
        }

        if existing:
            existing.write(rule_data)
            _logger.info(f"Updated access rule: {rule_name}")
        else:
            self.env['ir.model.access'].create(rule_data)
            _logger.info(f"Created access rule: {rule_name}")