<?php
namespace B3it\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;

class Adfs extends GenericProvider
{
    private $responseResourceOwnerId = 'upn';

    private $scopes = ['openid'];

    protected $idToken = null;

    protected $resource = null;

    /**
     * ADFS URL, eg. https://localhost/adfs.
     *
     * @var string
     */
    public $authServerUrl = null;

    public function __construct(array $options = [], array $collaborators = [])
    {
        if (isset($options['idToken'])) {
            $token = $options['idToken'];
            if ($token instanceof AccessToken) {
                $options['idToken'] = $this->getIdTokenFromAccessToken($token);
            }
        }
        parent::__construct($options, $collaborators);
    }

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->getBaseUrl().'/oauth2/authorize/';
    }

    /**
     * Get access token url to retrieve token
     *
     * @param  array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->getBaseUrl().'/oauth2/token/';
    }

    /**
     * Builds the logout URL.
     *
     * @param array $options
     * @return string Authorization URL
     */
    public function getLogoutUrl(array $options = [])
    {
        $base = $this->getBaseLogoutUrl();
        $params = $this->getAuthorizationParameters($options);
        if (isset($params['redirect_uri'])) {
            $params['post_logout_redirect_uri'] = $params['redirect_uri'];
            unset($params['redirect_uri']);
            if ($this->idToken) {
                $params['id_token_hint'] = $this->idToken;
            }
        }
        $query = $this->getAuthorizationQuery($params);
        return $this->appendQuery($base, $query);
    }

    public function getAccessToken($grant, array $options = [])
    {
        $token = parent::getAccessToken($grant, $options);

        //We have to preserve the id_token for id_token_hint in the logout url
        $this->idToken = $this->getIdTokenFromAccessToken($token);
        return $token;
    }

    /**
     * Requests and returns the resource owner of given access token.
     *
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(AccessToken $token)
    {
        $response = [];

        return $this->createResourceOwner($response, $token);
    }

    public function getIdTokenFromAccessToken($token) {
        if (!($token instanceof AccessToken)) {
            return null;
        }

        $values = $token->getValues();
        return $values['id_token'] ?? null;
    }

    public function getIdToken() {
        return $this->idToken;
    }

    public function getDefaultScopes()
    {
        $defaults = parent::getDefaultScopes();

        if (is_array($defaults)) {
            return array_merge($defaults, $this->scopes);
        }
        return $this->scopes;
    }

    /**
     * Get logout url to logout of session token
     *
     * @return string
     */
    private function getBaseLogoutUrl()
    {
        return $this->getBaseUrl() . '/oauth2/logout';
    }

    /**
     * Returns all options that are required.
     *
     * @return array
     */
    protected function getRequiredOptions()
    {
        return [
            'authServerUrl',
        ];
    }

    /**
     * Creates base url from provider configuration.
     *
     * @return string
     */
    protected function getBaseUrl()
    {
        return trim($this->authServerUrl, " \t\n\r\0\x0B/");
    }

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new AdfsResourceOwner($token, $response, $this->responseResourceOwnerId);
    }

    /**
     * Returns the list of options that can be passed to the HttpClient
     *
     * @param array $options An array of options to set on this provider.
     *     Options include `clientId`, `clientSecret`, `redirectUri`, and `state`.
     *     Individual providers may introduce more options, as needed.
     * @return array The options to pass to the HttpClient constructor
     */
    protected function getAllowedClientOptions(array $options)
    {
        $client_options = ['timeout', 'proxy', 'verify'];

        return $client_options;
    }

    protected function getAuthorizationParameters(array $options)
    {
        $params = parent::getAuthorizationParameters($options);

        if ($this->resource) {
            $params['resource'] = $this->resource;
        }

        return $params;
    }
}