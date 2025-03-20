<?php

namespace Iperson1337\PimcoreKeycloakBundle\EventListener;

use Psr\Log\LoggerInterface;
use Iperson1337\PimcoreKeycloakBundle\Security\User\KeycloakUser;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

readonly class AuthenticationSuccessListener implements EventSubscriberInterface
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();

        if (!$user instanceof KeycloakUser) {
            return;
        }

        $this->logger->info('Успешная аутентификация пользователя Keycloak: ' . $user->getUserIdentifier());

        // Здесь можно добавить дополнительную логику, которая должна выполняться при успешной аутентификации
        // Например, аудит, обновление статистики и т.д.
    }
}
