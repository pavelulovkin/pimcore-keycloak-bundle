pimcore.registerNS("pimcore.plugin.PimcoreKeycloakBundle");

pimcore.plugin.PimcoreKeycloakBundle = Class.create({

    initialize: function () {
        document.addEventListener(pimcore.events.pimcoreReady, this.pimcoreReady.bind(this));
    },

    pimcoreReady: function (e) {
        // Add Keycloak login option to user menu
        this.addKeycloakMenuItem();
    },

    addKeycloakMenuItem: function() {
        var menu = pimcore.globalmanager.get("layout_toolbar").userMenu;

        menu.add('-');
        menu.add({
            text: t('keycloak_account'),
            iconCls: 'pimcore_icon_user',
            handler: function() {
                window.open('/admin/keycloak/account', '_blank');
            }
        });
    }
});

var PimcoreKeycloakBundlePlugin = new pimcore.plugin.PimcoreKeycloakBundle();
