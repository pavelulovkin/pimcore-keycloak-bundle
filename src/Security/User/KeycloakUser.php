<?php

namespace Iperson1337\PimcoreKeycloakBundle\Security\User;

use Pimcore\Model\User;
use Symfony\Component\Security\Core\User\UserInterface;

class KeycloakUser implements UserInterface
{
    private string $username;
    private array $roles = [];
    private ?User $pimcoreUser = null;
    private ?string $keycloakId = null;
    private ?string $email = null;
    private ?string $firstName = null;
    private ?string $lastName = null;
    private array $keycloakRoles = [];
    private array $keycloakData = [];

    public function __construct(string $username, array $keycloakRoles = [], array $keycloakData = [])
    {
        $this->username = $username;
        $this->keycloakRoles = $keycloakRoles;
        $this->keycloakData = $keycloakData;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getRoles(): array
    {
        $roles = $this->roles;
        $roles[] = 'ROLE_PIMCORE_USER';

        return array_unique($roles);
    }

    public function setRoles(array $roles): self
    {
        $this->roles = $roles;

        return $this;
    }

    public function addRole(string $role): self
    {
        if (!in_array($role, $this->roles, true)) {
            $this->roles[] = $role;
        }

        return $this;
    }

    public function getPimcoreUser(): ?User
    {
        return $this->pimcoreUser;
    }

    public function setPimcoreUser(?User $pimcoreUser): self
    {
        $this->pimcoreUser = $pimcoreUser;

        return $this;
    }

    public function getKeycloakId(): ?string
    {
        return $this->keycloakId;
    }

    public function setKeycloakId(?string $keycloakId): self
    {
        $this->keycloakId = $keycloakId;

        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(?string $email): self
    {
        $this->email = $email;

        return $this;
    }

    public function getFirstName(): ?string
    {
        return $this->firstName;
    }

    public function setFirstName(?string $firstName): self
    {
        $this->firstName = $firstName;

        return $this;
    }

    public function getLastName(): ?string
    {
        return $this->lastName;
    }

    public function setLastName(?string $lastName): self
    {
        $this->lastName = $lastName;

        return $this;
    }

    public function getKeycloakRoles(): array
    {
        return $this->keycloakRoles;
    }

    public function setKeycloakRoles(array $keycloakRoles): self
    {
        $this->keycloakRoles = $keycloakRoles;

        return $this;
    }

    public function getKeycloakData(): array
    {
        return $this->keycloakData;
    }

    public function setKeycloakData(array $keycloakData): self
    {
        $this->keycloakData = $keycloakData;

        return $this;
    }

    /**
     * @return string
     */
    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    public function eraseCredentials(): void
    {
        // Не хранит чувствительных данных
    }
}
