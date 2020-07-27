/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.atlas.web.security;

import com.auth0.jwk.*;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@Component
public class AtlasJWTAuthenticationProvider extends AtlasAbstractAuthenticationProvider {
    private static Logger LOG = LoggerFactory.getLogger(AtlasJWTAuthenticationProvider.class);

    @PostConstruct
    public void setup() {
    }

    @Override
    public Authentication authenticate(Authentication authentication) {

        String username = authentication.getName();
        String userPassword = "";
        if (authentication.getCredentials() != null) {
            userPassword = authentication.getCredentials().toString(); //Pass JWT token here
        }

        if (JWT.authenticate(userPassword)) {
            List<GrantedAuthority> grantedAuths = new ArrayList<>();
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            Authentication auth = new UsernamePasswordAuthenticationToken(
                    username,
                    "password",
                    grantedAuths);
            return auth;
        }

        LOG.error("JWT Authentication Failed");
        return null;
    }


}

class JWT {
    static boolean authenticate(final String token) {
        try {
            // URL url = new URL("https://sts.windows.net/<AD Tenant ID>/.well-known/openid-configuration"); // TODO: Should be using this
            URL url = new URL("https://login.windows.net/common/discovery/keys"); // TODO: This shouldn't be used as this can be dynamic
            JwkProvider provider = new UrlJwkProvider(url);

            DecodedJWT jwt = com.auth0.jwt.JWT.decode(token);
            Jwk jwk = provider.get(jwt.getKeyId());

            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            algorithm.verify(jwt);
            return true;
        } catch (InvalidPublicKeyException e) {
            e.printStackTrace();
            System.out.println("ERROR: Authentication Failed due to Invalid Public Key");
            return false;
        } catch (JwkException e) {
            e.printStackTrace();
            System.out.println("ERROR: Authentication Failed due to JWK Exception");
            return false;
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            System.out.println("ERROR: Authentication Failed due to invalid signature");
            return false;
        } catch (MalformedURLException e) {
            e.printStackTrace();
            System.out.println("ERROR: Authentication Failed due to malformed key provider url");
            return false;
        }
    }
}