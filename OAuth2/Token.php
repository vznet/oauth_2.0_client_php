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

namespace OAuth2;

class Token
{
    /**
     * @var string
     */
    private $_accessToken;

    /**
     * @var string
     */
    private $_refreshToken;

    /**
     * @var string
     */
    private $_lifeTime;

    /**
     * @var array
     */
    private $_additionalParams = array();
    /**
     *
     * @param string $accessToken
     * @param string $refreshToken
     * @param int $lifeTime
     */
    public function __construct($accessToken = null, $refreshToken = null, $lifeTime = null) {
        $this->_accessToken = $accessToken;
        $this->_refreshToken = $refreshToken;
        if ($lifeTime) {
            $this->_lifeTime = ((int)$lifeTime) + time();
        }
    }

    /**
     * magic method for setting and getting additional parameters returned from
     * service
     *
     * e.g. user_id parameter with scope openid
     *
     * @param string $name
     * @param array $arguments
     * @return mixed
     */
    public function __call($name, $arguments) {
        if (strlen($name) < 4) {
            throw new Exception('undefined magic method called');
        }
        $method = substr($name, 0, 3);
        $param  = substr($name, 3);
        switch ($method) {
            case 'get':
                if (! isset($this->_additionalParams[$param])) {
                    throw new Exception($param . ' was not returned by service');
                }
                return $this->_additionalParams[$param];
            case 'set':
                if (! array_key_exists(0, $arguments)) {
                    throw new Exception('magic setter has no argument');
                }
                $this->_additionalParams[$param] = $arguments[0];
                break;
            default:
                throw new Exception('undefined magic method called');
        }
    }

    /**
     * @return string
     */
    public function getAccessToken() {
        return $this->_accessToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken() {
        return $this->_refreshToken;
    }

    /**
     * @return int
     */
    public function getLifeTime() {
        return $this->_lifeTime;
    }
}
