<?php

namespace Iperson1337\PimcoreKeycloakBundle\Service;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use League\OAuth2\Client\Provider\AbstractProvider;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Сервис для взаимодействия с API Keycloak
 */
class KeycloakService
{
    private HttpClientInterface $httpClient;

    public function __construct(
        private readonly ClientRegistry  $clientRegistry,
        private readonly LoggerInterface $logger,
        private readonly array $config
    ) {
        $this->httpClient = HttpClient::create();
    }

    /**
     * Получает информацию о текущем состоянии сервера Keycloak
     */
    public function getServerInfo(): array
    {
        $provider = $this->getKeycloakProvider();
        $baseUrl = $provider->getBaseUrl();

        try {
            $response = $this->httpClient->request('GET', $baseUrl . '/health');

            if ($response->getStatusCode() === 200) {
                return [
                    'status' => 'OK',
                    'server_url' => $baseUrl,
                    'data' => json_decode($response->getContent(), true)
                ];
            }

            return [
                'status' => 'ERROR',
                'message' => 'Keycloak server is not responding properly',
                'code' => $response->getStatusCode()
            ];
        } catch (ExceptionInterface $e) {
            $this->logger->error('Error checking Keycloak server: ' . $e->getMessage());

            return [
                'status' => 'ERROR',
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Получает список пользователей из Keycloak (требуется административный доступ)
     */
    public function getUsers(string $accessToken, int $limit = 100, int $offset = 0): array
    {
        $provider = $this->getKeycloakProvider();
        $url = $provider->getBaseApiUrlWithRealm() . '/users';

        try {
            $response = $this->httpClient->request('GET', $url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken,
                    'Content-Type' => 'application/json'
                ],
                'query' => [
                    'max' => $limit,
                    'first' => $offset
                ]
            ]);

            if ($response->getStatusCode() === 200) {
                return json_decode($response->getContent(), true);
            }

            $this->logger->error('Error fetching Keycloak users', [
                'code' => $response->getStatusCode(),
                'content' => $response->getContent(false)
            ]);

            return [];
        } catch (ExceptionInterface $e) {
            $this->logger->error('Exception fetching Keycloak users: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Находит пользователя в Keycloak по email
     */
    public function findUserByEmail(string $accessToken, string $email): ?array
    {
        $provider = $this->getKeycloakProvider();
        $url = $provider->getBaseApiUrlWithRealm() . '/users';

        try {
            $response = $this->httpClient->request('GET', $url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken,
                    'Content-Type' => 'application/json'
                ],
                'query' => [
                    'email' => $email,
                    'exact' => 'true'
                ]
            ]);

            if ($response->getStatusCode() === 200) {
                $users = json_decode($response->getContent(), true);
                return !empty($users) ? $users[0] : null;
            }

            return null;
        } catch (ExceptionInterface $e) {
            $this->logger->error('Exception finding Keycloak user by email: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Получает OAuth2 провайдер Keycloak
     */
    private function getKeycloakProvider(): AbstractProvider
    {
        return $this->clientRegistry->getClient('keycloak')->getOAuth2Provider();
    }
}
