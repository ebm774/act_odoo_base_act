/** @odoo-module **/

import { registry } from "@web/core/registry";
import { Component, useState, onWillStart } from "@odoo/owl";

class UserInfoSystray extends Component {
    setup() {
        super.setup();

        this.state = useState({
            userName: 'Loading...',
            departmentName: 'Loading...',
            isLoaded: false
        });

        onWillStart(async () => {
            await this.loadUserInfo();
        });
    }

    async loadUserInfo() {
        try {
            // First try session info
            const sessionInfo = odoo.session_info || {};
            let userName = sessionInfo.name || sessionInfo.username || 'Unknown User';
            let departmentName = 'No Department';

            // Check if department is in session context
            if (sessionInfo.user_context?.department_name) {
                departmentName = sessionInfo.user_context.department_name;
            } else if (sessionInfo.department_name) {
                departmentName = sessionInfo.department_name;
            } else {
                // Fallback: fetch via controller
                try {
                    const response = await fetch('/web/user_info', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify({
                            jsonrpc: "2.0",
                            method: "call",
                            params: {},
                            id: new Date().getTime()
                        })
                    });

                    if (response.ok) {
                        const data = await response.json();
                        if (data.result) {
                            userName = data.result.name || userName;
                            departmentName = data.result.department_name || 'No Department';
                        }
                    }
                } catch (fetchError) {
                    console.warn("Could not fetch user info via controller:", fetchError);
                }
            }

            this.state.userName = userName;
            this.state.departmentName = departmentName;
            this.state.isLoaded = true;

        } catch (error) {
            console.error("Failed to load user info:", error);
            this.state.userName = odoo.session_info?.name || 'Error';
            this.state.departmentName = 'Error';
            this.state.isLoaded = true;
        }
    }
}

UserInfoSystray.template = "user_info_systray_template";

export const userInfoSystrayItem = {
    Component: UserInfoSystray,
};

registry.category("systray").add("UserInfoSystray", userInfoSystrayItem, {
    sequence: 10
});