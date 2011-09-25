<?php
/**
 * Copyright (c) 2010 VZnet Netzwerke Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author    Bastian Hofmann <bhfomann@vz.net>
 * @author    Vyacheslav Slinko <vyacheslav.slinko@gmail.com>
 * @copyright 2010 VZnet Netzwerke Ltd.
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace OAuth2\Service;

class Configuration
{
    const AUTHORIZATION_METHOD_HEADER = 1;
    const AUTHORIZATION_METHOD_ALTERNATIVE = 2;

    /**
     * @var string
     */
    private $_authorizeEndpoint;

    /**
     * @var string
     */
    private $_accessTokenEndpoint;

    /**
     * @var string
     */
    private $_authorizationMethod = self::AUTHORIZATION_METHOD_HEADER;

    /**
     * @param string $authorizeEndpoint
     * @param string $accessTokenEndpoint
     */
    public function __construct($authorizeEndpoint, $accessTokenEndpoint) {
        $this->_authorizeEndpoint = $authorizeEndpoint;
        $this->_accessTokenEndpoint = $accessTokenEndpoint;
    }

    /**
     * @return string
     */
    public function getAuthorizeEndpoint() {
        return $this->_authorizeEndpoint;
    }

    /**
     * @return string
     */
    public function getAccessTokenEndpoint() {
        return $this->_accessTokenEndpoint;
    }

    /**
     * @return string
     */
    public function setAuthorizationMethod($authorizationMethod) {
         $this->_authorizationMethod = $authorizationMethod;
    }

    /**
     * @return string
     */
    public function getAuthorizationMethod() {
        return $this->_authorizationMethod;
    }

}
