<?php

namespace Iperson1337\PimcoreKeycloakBundle;

use Pimcore\Extension\Bundle\Installer\SettingsStoreAwareInstaller;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Bundle\BundleInterface;
use Symfony\Component\Yaml\Yaml;

class Installer extends SettingsStoreAwareInstaller
{
    private string $projectDir;
    private Filesystem $filesystem;

    public function __construct(
        protected BundleInterface $bundle
    ) {
        $this->projectDir = $this->bundle->getPath();
        $this->filesystem = new Filesystem();

        parent::__construct($bundle);
    }

    public function install(): void
    {
        $this->installFiles();
        parent::install();
    }

    public function uninstall(): void
    {
        $this->removeFiles();
        parent::uninstall();
    }

    /**
     * Устанавливает необходимые файлы конфигурации
     */
    private function installFiles(): void
    {
        // Создаем директорию для конфигураций, если она не существует
        $configDir = $this->projectDir . '/config/packages';
        if (!$this->filesystem->exists($configDir)) {
            $this->filesystem->mkdir($configDir, 0755);
        }

        // Копируем конфигурацию бандла
        $this->filesystem->copy(
            __DIR__ . '/../config/packages/iperson1337_pimcore_keycloak.yaml',
            $this->projectDir . '/config/packages/iperson1337_pimcore_keycloak.yaml'
        );

        // Добавляем конфигурацию в security.yaml или создаем новый файл
        $securityFile = $this->projectDir . '/config/packages/security.yaml';
        if ($this->filesystem->exists($securityFile)) {
            $this->updateSecurityConfig($securityFile);
        } else {
            $this->createSecurityConfig($securityFile);
        }

        // Создание .env файла для переменных окружения Keycloak, если его еще нет
        $envFile = $this->projectDir . '/.env.local';
        if (!$this->filesystem->exists($envFile)) {
            $this->createEnvFile($envFile);
        } else {
            $this->updateEnvFile($envFile);
        }
    }

    /**
     * Удаляет установленные файлы конфигурации
     */
    private function removeFiles(): void
    {
        $files = [
            $this->projectDir . '/config/packages/iperson1337_pimcore_keycloak.yaml',
        ];

        foreach ($files as $file) {
            if ($this->filesystem->exists($file)) {
                $this->filesystem->remove($file);
            }
        }

        // Очистка security.yaml от настроек Keycloak
        $securityFile = $this->projectDir . '/config/packages/security.yaml';
        if ($this->filesystem->exists($securityFile)) {
            $this->removeKeycloakFromSecurityConfig($securityFile);
        }
    }

    /**
     * Обновляет существующий security.yaml, добавляя в него настройки Keycloak
     */
    private function updateSecurityConfig(string $securityFile): void
    {
        $securityConfig = Yaml::parseFile($securityFile);

        // Добавляем провайдер keycloak
        if (!isset($securityConfig['security']['providers']['keycloak_provider'])) {
            $securityConfig['security']['providers']['keycloak_provider'] = [
                'id' => 'Iperson1337\PimcoreKeycloakBundle\Security\User\KeycloakUserProvider',
            ];
        }

        // Активируем новый AuthenticatorManager, если он еще не активирован
        $securityConfig['security']['enable_authenticator_manager'] = true;

        // Обновляем или добавляем настройки для admin firewall
        if (!isset($securityConfig['security']['firewalls']['admin'])) {
            $securityConfig['security']['firewalls']['admin'] = [
                'pattern' => '^/admin',
                'provider' => 'keycloak_provider',
                'custom_authenticators' => [
                    'Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator',
                ],
                'entry_point' => 'Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator',
                'logout' => [
                    'path' => 'iperson1337_pimcore_keycloak_logout',
                    'target' => 'pimcore_admin_login',
                ],
            ];
        } else {
            // Обновляем существующий firewall admin
            $adminFirewall = &$securityConfig['security']['firewalls']['admin'];
            $adminFirewall['provider'] = 'keycloak_provider';

            if (!isset($adminFirewall['custom_authenticators'])) {
                $adminFirewall['custom_authenticators'] = [];
            }

            if (!in_array('Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator', $adminFirewall['custom_authenticators'])) {
                $adminFirewall['custom_authenticators'][] = 'Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator';
            }

            $adminFirewall['entry_point'] = 'Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator';
            $adminFirewall['logout'] = [
                'path' => 'iperson1337_pimcore_keycloak_logout',
                'target' => 'pimcore_admin_login',
            ];
        }

        // Сохраняем обновленную конфигурацию
        file_put_contents($securityFile, Yaml::dump($securityConfig, 6));
    }

    /**
     * Создает новый файл security.yaml с настройками Keycloak
     */
    private function createSecurityConfig(string $securityFile): void
    {
        $securityConfig = [
            'security' => [
                'enable_authenticator_manager' => true,
                'providers' => [
                    'keycloak_provider' => [
                        'id' => 'Iperson1337\PimcoreKeycloakBundle\Security\User\KeycloakUserProvider',
                    ],
                ],
                'firewalls' => [
                    'admin' => [
                        'pattern' => '^/admin',
                        'provider' => 'keycloak_provider',
                        'custom_authenticators' => [
                            'Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator',
                        ],
                        'entry_point' => 'Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator',
                        'logout' => [
                            'path' => 'iperson1337_pimcore_keycloak_logout',
                            'target' => 'pimcore_admin_login',
                        ],
                    ],
                ],
            ],
        ];

        // Сохраняем конфигурацию в файл
        file_put_contents($securityFile, Yaml::dump($securityConfig, 6));
    }

    /**
     * Удаляет настройки Keycloak из security.yaml
     */
    private function removeKeycloakFromSecurityConfig(string $securityFile): void
    {
        $securityConfig = Yaml::parseFile($securityFile);

        // Удаляем провайдер keycloak
        if (isset($securityConfig['security']['providers']['keycloak_provider'])) {
            unset($securityConfig['security']['providers']['keycloak_provider']);
        }

        // Удаляем аутентификатор из admin firewall
        if (isset($securityConfig['security']['firewalls']['admin']['custom_authenticators'])) {
            $authenticators = &$securityConfig['security']['firewalls']['admin']['custom_authenticators'];
            $key = array_search('Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator', $authenticators);
            if ($key !== false) {
                unset($authenticators[$key]);
                // Переиндексируем массив
                $authenticators = array_values($authenticators);
            }
        }

        // Сохраняем обновленную конфигурацию
        file_put_contents($securityFile, Yaml::dump($securityConfig, 6));
    }

    /**
     * Создает файл .env.local с настройками Keycloak
     */
    private function createEnvFile(string $envFile): void
    {
        $envContent = <<<EOT
# Keycloak OAuth Configuration
KEYCLOAK_SERVER_BASE_URL=https://keycloak.example.com
KEYCLOAK_SERVER_PUBLIC_BASE_URL=https://keycloak.example.com
KEYCLOAK_SERVER_PRIVATE_BASE_URL=https://keycloak.example.com
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=pimcore-client
KEYCLOAK_CLIENT_SECRET=your-client-secret

EOT;

        file_put_contents($envFile, $envContent);
    }

    /**
     * Обновляет существующий .env.local, добавляя в него настройки Keycloak
     */
    private function updateEnvFile(string $envFile): void
    {
        $envContent = file_get_contents($envFile);

        // Проверяем, есть ли уже настройки Keycloak
        if (!str_contains($envContent, 'KEYCLOAK_SERVER_BASE_URL')) {
            $keycloakConfig = <<<EOT

# Keycloak OAuth Configuration
KEYCLOAK_SERVER_BASE_URL=https://keycloak.example.com
KEYCLOAK_SERVER_PUBLIC_BASE_URL=https://keycloak.example.com
KEYCLOAK_SERVER_PRIVATE_BASE_URL=https://keycloak.example.com
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=pimcore-client
KEYCLOAK_CLIENT_SECRET=your-client-secret

EOT;

            file_put_contents($envFile, $envContent . $keycloakConfig);
        }
    }
}
