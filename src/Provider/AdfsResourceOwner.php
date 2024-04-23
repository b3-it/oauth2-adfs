<?php
namespace B3it\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;

class AdfsResourceOwner extends GenericResourceOwner
{
    protected $token = null;

    /**
     * @param AccessToken $token
     * @param array $response
     * @param string $resourceOwnerId
     */
    public function __construct(AccessToken $token, array $response, $resourceOwnerId)
    {
        parent::__construct($response, $resourceOwnerId);
        $this->token = $token;

        $data = $this->parseToken($token);

        foreach ($data as $key => $value) {
            if (!is_string($key)) {
                continue;
            }
            $this->$key = $value;
        }
    }

    /**
     * Get resource owner email
     *
     * @return string|null
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * Get resource owner name
     *
     * @return string|null
     */
    public function getName()
    {
        return $this->given_name;
    }

    /**
     * Return all of the owner details available as an array.
     *
     * @return array
     */
    public function toArray()
    {
        $data =  $this->parseToken($this->token);
        if (!is_array($data)) {
            return [];
        }

        return $data;
    }

    /**
     * Parse base64 coded token to array
     *
     * @param AccessToken $token
     * @return array
     */
    protected function parseToken(AccessToken $accessToken) {
        if (is_string($accessToken)) {
            return null;
        }

        $tokenValues = $accessToken->getValues();

        $tokens = [];
        if (isset($tokenValues['id_token'])) {
            $tokens[] = $tokenValues['id_token'];
        }
        $tokens[] = $accessToken->getToken();

        $data = [];
        foreach ($tokens as $token) {
            $token = mb_split('\.', $token);
            /*
             * First part contains JWT information
             * User info is stored in second part
             */
            if (!isset($token[1])) {
                continue;
            }
            $token = $token[1];
            $json = base64_decode(strtr($token, '-_', '+/'));

            if (!is_string($json)) {
                continue;
            }

            $newData = json_decode($json, true);

            if (!is_array($newData)) {
                continue;
            }

            $data = array_merge($data, $newData);
        }
        return $data;
    }

    public function getIdToken($token = null) {
        if (!$token) {
            $token = $this->token;
        }

        if (!($token instanceof AccessToken)) {
            return null;
        }

        $values = $token->getValues();
        return $values['id_token'] ?? null;
    }
}