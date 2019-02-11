# Our NiFi configs

For Ambari 2.7.3 and HDF 3.3.1.0

Includes:
- Identity Mapping
- Creation of nifi identities and policies in Ranger
- SSL
- KnoxSSO for authentication
- LDAP for user-group information
- Ranger for authorization in conjection with the ldap-user-group-provider
- Compression of rotated logs

## Identity Mapping

Advanced nifi-properties:
```
nifi.security.group.mapping.pattern.anygroup=^(.*)$
nifi.security.group.mapping.transform.anygroup=LOWER
nifi.security.group.mapping.value.anygroup=$1
nifi.security.identity.mapping.pattern.dn=^CN=(.*?), OU=(.*?)$
nifi.security.identity.mapping.transform.dn=LOWER
nifi.security.identity.mapping.value.dn=$1
nifi.security.identity.mapping.pattern.kerb=^(.*?)@(.*?)$
nifi.security.identity.mapping.transform.kerb=LOWER
nifi.security.identity.mapping.value.kerb=$1
```

Custom nifi-properties:
```
nifi.security.identity.mapping.pattern.cert=^CN=(.*?), OU=(.*?), O=(.*?), L=(.*?), ST=(.*?), C=(.*?)$
nifi.security.identity.mapping.value.cert=$1
nifi.security.identity.mapping.transform.cert=LOWER
nifi.security.identity.mapping.pattern.certreverse=^C=(.*?), ST=(.*?), L=(.*?), O=(.*?), OU=(.*?), CN=(.*?)$
nifi.security.identity.mapping.value.certreverse=$6
nifi.security.identity.mapping.transform.certreverse=LOWER
nifi.security.identity.mapping.pattern.zzzanyuser=^(.*)$
nifi.security.identity.mapping.transform.zzzanyuser=LOWER
nifi.security.identity.mapping.value.zzzanyuser=$1
```

From the Ambari & Ranger host. This needs adjusting if they are on different hosts:
```
sudo yum install python-configparser jq pwgen

read -p "Enter password:" -s ambari_pass

ambari_user=admin
ambari_protocol=https
ambari_port=8443
ambari_host=$(python -c "import configparser; c = configparser.ConfigParser(); c.read('/etc/ambari-agent/conf/ambari-agent.ini'); print(c['server']['hostname'])")

ambari_api="${ambari_protocol}://localhost:${ambari_port}/api/v1"
ambari_curl_cmd="curl -ksS -u ${ambari_user}:${ambari_pass} -H x-requested-by:curl"
export ambari_curl="${ambari_curl_cmd} ${ambari_api}"
ambari_cluster=$(${ambari_curl}/clusters | python -c 'import sys,json; \
            print json.load(sys.stdin)["items"][0]["Clusters"]["cluster_name"]')
echo ${ambari_cluster}

nifi_hosts=$(${ambari_curl}"/clusters/${ambari_cluster}/services/NIFI/components/NIFI_MASTER?fields=host_components/HostRoles/host_name" | jq -r '.host_components[].HostRoles.host_name')

nifi_hosts_json=$(${ambari_curl}"/clusters/${ambari_cluster}/services/NIFI/components/NIFI_MASTER?fields=host_components/HostRoles/host_name" | jq '.host_components[].HostRoles.host_name' | jq -r '[.]' | jq -s -c 'add')

echo ${nifi_hosts}

echo ${nifi_hosts_json}

## Create ranger_curl commands to re-use
keytab=/etc/security/keytabs/rangerusersync.service.keytab
sudo -u ranger kinit -kt ${keytab} $(sudo -u ranger klist -kt ${keytab}| awk '{print $NF}'|tail -1)
ranger_curl="sudo -u ranger curl -vksS -u: --negotiate -H Accept:application/json -H Content-Type:application/json -H x-requested-by:opserv-keel https://$(hostname -f):6182"
ranger_curl="sudo -u ranger curl -vksS -u: --negotiate -H Accept:application/json -H Content-Type:application/json -H x-requested-by:opserv-keel http://$(hostname -f):6080"
 
## In Ranger, create "nifi-hosts" group
read -r -d '' body <<EOF
{"name":"nifi-hosts","description":"nifi-hosts"}
EOF
group_id=$(echo "${body}" | ${ranger_curl}"/service/xusers/secure/groups" -X POST -d @- | jq '.id')

## Create users for each host
for nifi_host in ${nifi_hosts}; do
  read -r -d '' body <<EOF
{ "name":"${nifi_host}",
  "firstName":"${nifi_host}",
  "loginId": "${nifi_host}",
  "emailAddress" : null,
  "password" : "$(pwgen 32 1)",
  "groupIdList":[${group_id}],
  "status":1,
  "isVisible":1,
  "userRoleList": ["ROLE_USER"]
}
EOF
  echo "${body}" | ${ranger_curl}/service/xusers/secure/users -X POST -d @-
done

read -r -d '' body <<EOF
{"policyType":"0","name":"nifi-hosts","isEnabled":true,"policyPriority":0,"policyLabels":[""],"description":"","isAuditEnabled":true,"resources":{"nifi-resource":{"values":["/proxy","/controller"],"isRecursive":false,"isExcludes":false}},"policyItems":[{"users":${nifi_hosts_json},"groups":["nifi-hosts"],"accesses":[{"type":"READ","isAllowed":true},{"type":"WRITE","isAllowed":true}]}],"denyPolicyItems":[],"allowExceptions":[],"denyExceptions":[],"service":"${ambari_cluster}_nifi"}
EOF
body=$(echo ${body} | jq '.')
echo "${body}" | ${ranger_curl}"/service/plugins/policies" -X POST -d @-
```

--------

## SSL

Advanced nifi-ambari-config
```
nifi.node.port=
```

Advanced nifi-properties:
```
nifi.web.http.port=
```

Advanced nifi-ambari-ssl-config:
```
nifi.initial.admin.identity=username-of-a-nifi-admin

nifi.ssl.isenabled=true
```

Advanced nifi-ambari-ssl-config Node identities "content": Add line for each of the nifi hosts. This is the CN= in their SSL certificate.
```
<property name="Node Identity 1">fqdn-of-nifi-host-1.foo.example.com</property>
<property name="Node Identity 2">fqdn-of-nifi-host-2.foo.example.com</property>
<property name="Node Identity 3">fqdn-of-nifi-host-2.foo.example.com</property>
```

#### ONLY IF using your own certificates instead of NiFi CA:

advanced nifi-ambari-ssl-config:
```
nifi.security.keystore=/etc/security/serverKeys/keystore.jks
nifi.security.keystoreType=JKS
nifi.security.truststore=/etc/pki/java/cacerts
nifi.security.truststoreType=JKS
```

advanced nifi-ambari-ssl-config password fields:
```
nifi.security.keystorePasswd=changeit
nifi.security.keyPasswd=changeit
nifi.security.truststorePasswd=changeit
```

advanced nifi-properties password fields:
```
nifi.security.keyPasswd={{config['configurations']['nifi-ambari-ssl-config']['nifi.security.keyPasswd']}}
nifi.security.keystorePasswd={{config['configurations']['nifi-ambari-ssl-config']['nifi.security.keystorePasswd']}}
nifi.security.truststorePasswd={{config['configurations']['nifi-ambari-ssl-config']['nifi.security.truststorePasswd']}}
```

--------

## KnoxSSO:

Fetch certificate from Knox host:
```
knox_host=knox-host.foo.customer.com
knox_port=8443
openssl s_client -connect ${knox_host}:${knox_port}</dev/null | openssl x509 -out /tmp/knox.crt
chmod 0444 /tmp/knox.crt
sudo mv /tmp/knox.crt /etc/pki/tls/certs/knox.crt
```

Advanced nifi-properties:
```
nifi.security.user.login.identity.provider=
nifi.security.user.knox.publicKey=/etc/pki/tls/certs/knox.crt   
nifi.security.user.knox.url=https://knox-host.foo.customer.com:8443/gateway/knoxsso/api/v1/websso 
```

----

## LDAP

Custom nifi-authorizers-env:
```
ldap-manager-dn=ldap-bind-user
ldap-url=ldaps://ldapad.foo.example.com
ldap-user-search-base=DC=example,DC=com
ldap-user-search-filter=(|(memberOf=CN=nifi-users,OU=foo,DC=example,DC=com))
ldap-group-search-base=DC=example,DC=com
ldap-group-search-filter=(|(cn=nifi-usrs)(cn=nifi-admins))

ldap-tls-keystore=/etc/security/serverKeys/keystore.jks
ldap-tls-truststore=/etc/pki/java/cacerts
ldap-tls-keystore-type=jks
ldap-tls-truststore-type=jks

ldap-identity-strategy=USE_USERNAME
ldap-authentication-expiration=12 hours
ldap-authentication-strategy=LDAPS

ldap-tls-client-auth=
ldap-tls-protocol=TLS
ldap-tls-shutdown-gracefully=
ldap-referral-strategy=IGNORE
ldap-connect-timeout=10 secs
ldap-read-timeout=10 secs
ldap-page-size=
ldap-sync-interval=30 mins
ldap-user-object-class=user
ldap-user-search-scope=SUBTREE
ldap-user-identity-attribute=samaccountname
ldap-user-group-name-attribute=memberof
ldap-user-group-name-attribute-referenced-group-attribute=
ldap-group-object-class=group
ldap-group-search-scope=SUBTREE
ldap-group-name-attribute=samaccountname
ldap-group-member-attribute=member
ldap-group-name-attribute-referenced-user-attribute=
```

Custom nifi-authorizers-env password fields. Ensure to add as a PASSWORD type field:
```
ldap-manager-password=theLdapPass
ldap-tls-keystore-password=changeit
ldap-tls-truststore-password=changeit
```

Advanced nifi-authorizers-env: Template for authorizers.xml
```
<authorizers>

    {% if not (has_ranger_admin and enable_ranger_nifi) %}
    <userGroupProvider>
        <identifier>file-user-group-provider</identifier>
        <class>org.apache.nifi.authorization.FileUserGroupProvider</class>
        <property name="Users File">{{nifi_flow_config_dir}}/users.xml</property>
        <property name="Legacy Authorized Users File"></property>
        <property name="Initial User Identity 0">{{nifi_initial_admin_id}}</property>
        {{nifi_ssl_config_content | replace("Node","Initial User")}}
    </userGroupProvider>

    <accessPolicyProvider>
        <identifier>file-access-policy-provider</identifier>
        <class>org.apache.nifi.authorization.FileAccessPolicyProvider</class>
        <property name="User Group Provider">file-user-group-provider</property>
        <property name="Authorizations File">{{nifi_flow_config_dir}}/authorizations.xml</property>
        <property name="Initial Admin Identity">{{nifi_initial_admin_id}}</property>
        <property name="Legacy Authorized Users File"></property>
        {{nifi_ssl_config_content}}
    </accessPolicyProvider>

    <authorizer>
        <identifier>{{nifi_authorizer}}</identifier>
        <class>org.apache.nifi.authorization.StandardManagedAuthorizer</class>
        <property name="Access Policy Provider">file-access-policy-provider</property>
    </authorizer>
    
    {% else %}

    <userGroupProvider>
        <identifier>ldap-user-group-provider</identifier>
        <class>org.apache.nifi.ldap.tenants.LdapUserGroupProvider</class>
        <property name="Authentication Strategy">{{config['configurations']['nifi-authorizers-env']['ldap-authentication-strategy']}}</property>

        <property name="Manager DN">{{config['configurations']['nifi-authorizers-env']['ldap-manager-dn']}}</property>
        <property name="Manager Password">{{config['configurations']['nifi-authorizers-env']['ldap-manager-password']}}</property>

        <property name="TLS - Keystore">{{config['configurations']['nifi-authorizers-env']['ldap-tls-keystore']}}</property>
        <property name="TLS - Keystore Password">{{config['configurations']['nifi-authorizers-env']['ldap-tls-keystore-password']}}</property>
        <property name="TLS - Keystore Type">{{config['configurations']['nifi-authorizers-env']['ldap-tls-keystore-type']}}</property>
        <property name="TLS - Truststore">{{config['configurations']['nifi-authorizers-env']['ldap-tls-truststore']}}</property>
        <property name="TLS - Truststore Password">{{config['configurations']['nifi-authorizers-env']['ldap-tls-truststore-password']}}</property>
        <property name="TLS - Truststore Type">{{config['configurations']['nifi-authorizers-env']['ldap-tls-truststore-type']}}</property>
        <property name="TLS - Client Auth">{{config['configurations']['nifi-authorizers-env']['ldap-tls-client-auth']}}</property>
        <property name="TLS - Protocol">{{config['configurations']['nifi-authorizers-env']['ldap-tls-protocol']}}</property>
        <property name="TLS - Shutdown Gracefully">{{config['configurations']['nifi-authorizers-env']['ldap-tls-shutdown-gracefully']}}</property>

        <property name="Referral Strategy">{{config['configurations']['nifi-authorizers-env']['ldap-referral-strategy']}}</property>
        <property name="Connect Timeout">{{config['configurations']['nifi-authorizers-env']['ldap-connect-timeout']}}</property>
        <property name="Read Timeout">{{config['configurations']['nifi-authorizers-env']['ldap-read-timeout']}}</property>

        <property name="Url">{{config['configurations']['nifi-authorizers-env']['ldap-url']}}</property>
        <property name="Page Size">{{config['configurations']['nifi-authorizers-env']['ldap-page-size']}}</property>
        <property name="Sync Interval">{{config['configurations']['nifi-authorizers-env']['ldap-sync-interval']}}</property>

        <property name="User Search Base">{{config['configurations']['nifi-authorizers-env']['ldap-user-search-base']}}</property>
        <property name="User Object Class">{{config['configurations']['nifi-authorizers-env']['ldap-user-object-class']}}</property>
        <property name="User Search Scope">{{config['configurations']['nifi-authorizers-env']['ldap-user-search-scope']}}</property>
        <property name="User Search Filter">{{config['configurations']['nifi-authorizers-env']['ldap-user-search-filter']}}</property>
        <property name="User Identity Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-user-identity-attribute']}}</property>
        <property name="User Group Name Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-user-group-name-attribute']}}</property>
        <property name="User Group Name Attribute - Referenced Group Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-user-group-name-attribute-referenced-group-attribute']}}</property>

        <property name="Group Search Base">{{config['configurations']['nifi-authorizers-env']['ldap-group-search-base']}}</property>
        <property name="Group Object Class">{{config['configurations']['nifi-authorizers-env']['ldap-group-object-class']}}</property>
        <property name="Group Search Scope">{{config['configurations']['nifi-authorizers-env']['ldap-group-search-scope']}}</property>
        <property name="Group Search Filter">{{config['configurations']['nifi-authorizers-env']['ldap-group-search-filter']}}</property>
        <property name="Group Name Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-group-name-attribute']}}</property>
        <property name="Group Member Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-group-member-attribute']}}</property>
        <property name="Group Member Attribute - Referenced User Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-group-name-attribute-referenced-user-attribute']}}</property>
    </userGroupProvider>

    <authorizer>
        <identifier>{{nifi_authorizer}}</identifier>
        <class>org.apache.nifi.ranger.authorization.ManagedRangerAuthorizer</class>
        <property name="User Group Provider">ldap-user-group-provider</property>
        <property name="Ranger Audit Config Path">{{nifi_config_dir}}/ranger-nifi-audit.xml</property>
        <property name="Ranger Security Config Path">{{nifi_config_dir}}/ranger-nifi-security.xml</property>
        <property name="Ranger Service Type">nifi</property>
        <property name="Ranger Application Id">nifi</property>
        <property name="Ranger Admin Identity">{{ranger_admin_identity}}</property>
        {% if security_enabled %}
        <property name="Ranger Kerberos Enabled">true</property>
        {% else %}
        <property name="Ranger Kerberos Enabled">false</property>
        {% endif %}
    </authorizer>
    
    {% endif %}
</authorizers> 
```

--------

## Enable log compression

Template for logback.xml:
- Replace `.log</fileNamePattern>` with `.log.gz</fileNamePattern>`

--------

## Nifi-Registry



## Identity Mapping

Advanced nifi-registry-properties:
```
nifi.registry.security.identity.mapping.pattern.dn=^CN=(.*?), OU=(.*?)$
nifi.registry.security.identity.mapping.pattern.kerb=^(.*?)@(.*?)$
nifi.registry.security.identity.mapping.value.dn=$1
nifi.registry.security.identity.mapping.value.kerb=$1

nifi.registry.security.identity.provider=ldap-provider 
```

Custom nifi-registry-properties:
```
nifi.registry.security.group.mapping.pattern.anygroup=^(.*)$
nifi.registry.security.group.mapping.transform.anygroup=LOWER
nifi.registry.security.group.mapping.value.anygroup=$1
nifi.registry.security.identity.mapping.transform.dn=LOWER
nifi.registry.security.identity.mapping.transform.kerb=LOWER
nifi.registry.security.identity.mapping.pattern.cert=^CN=(.*?), OU=(.*?), O=(.*?), L=(.*?), ST=(.*?), C=(.*?)$
nifi.registry.security.identity.mapping.value.cert=$1
nifi.registry.security.identity.mapping.pattern.certreverse=^C=(.*?), ST=(.*?), L=(.*?), O=(.*?), OU=(.*?), CN=(.*?)$
nifi.registry.security.identity.mapping.value.certreverse=$6
nifi.registry.security.identity.mapping.transform.certreverse=LOWER
nifi.registry.security.identity.mapping.transform.cert=LOWER
nifi.registry.security.identity.mapping.pattern.zzzanyuser=^(.*)$
nifi.registry.security.identity.mapping.transform.zzzanyuser=LOWER
nifi.registry.security.identity.mapping.value.zzzanyuser=$1
```

nifi-registry-ambari-config:
```
nifi.registry.port=
```

nifi-registry-ambari-ssl-config:
```
nifi.registry.ssl.isenabled=true
nifi.registry.initial.admin.identity= copy the same config from nifi
node identities content= copy the same config from nifi
```

Advanced nifi-registry-authorizers-env
```
<authorizers>

    <userGroupProvider>
        <identifier>file-user-group-provider</identifier>
        <class>org.apache.nifi.registry.security.authorization.file.FileUserGroupProvider</class>
        <property name="Users File">{{nifi_registry_internal_config_dir}}/users.xml</property>
        {{nifi_registry_ssl_config_content | replace("NiFi","Initial User")}}
    </userGroupProvider>

    <userGroupProvider>
        <identifier>ldap-user-group-provider</identifier>
        <class>org.apache.nifi.registry.security.ldap.tenants.LdapUserGroupProvider</class>
        <property name="Authentication Strategy">{{config['configurations']['nifi-authorizers-env']['ldap-authentication-strategy']}}</property>

        <property name="Manager DN">{{config['configurations']['nifi-authorizers-env']['ldap-manager-dn']}}</property>
        <property name="Manager Password">{{config['configurations']['nifi-authorizers-env']['ldap-manager-password']}}</property>

        <property name="TLS - Keystore">{{config['configurations']['nifi-authorizers-env']['ldap-tls-keystore']}}</property>
        <property name="TLS - Keystore Password">{{config['configurations']['nifi-authorizers-env']['ldap-tls-keystore-password']}}</property>
        <property name="TLS - Keystore Type">{{config['configurations']['nifi-authorizers-env']['ldap-tls-keystore-type']}}</property>
        <property name="TLS - Truststore">{{config['configurations']['nifi-authorizers-env']['ldap-tls-truststore']}}</property>
        <property name="TLS - Truststore Password">{{config['configurations']['nifi-authorizers-env']['ldap-tls-truststore-password']}}</property>
        <property name="TLS - Truststore Type">{{config['configurations']['nifi-authorizers-env']['ldap-tls-truststore-type']}}</property>
        <property name="TLS - Client Auth">{{config['configurations']['nifi-authorizers-env']['ldap-tls-client-auth']}}</property>
        <property name="TLS - Protocol">{{config['configurations']['nifi-authorizers-env']['ldap-tls-protocol']}}</property>
        <property name="TLS - Shutdown Gracefully">{{config['configurations']['nifi-authorizers-env']['ldap-tls-shutdown-gracefully']}}</property>

        <property name="Referral Strategy">{{config['configurations']['nifi-authorizers-env']['ldap-referral-strategy']}}</property>
        <property name="Connect Timeout">{{config['configurations']['nifi-authorizers-env']['ldap-connect-timeout']}}</property>
        <property name="Read Timeout">{{config['configurations']['nifi-authorizers-env']['ldap-read-timeout']}}</property>

        <property name="Url">{{config['configurations']['nifi-authorizers-env']['ldap-url']}}</property>
        <property name="Page Size">{{config['configurations']['nifi-authorizers-env']['ldap-page-size']}}</property>
        <property name="Sync Interval">{{config['configurations']['nifi-authorizers-env']['ldap-sync-interval']}}</property>

        <property name="User Search Base">{{config['configurations']['nifi-authorizers-env']['ldap-user-search-base']}}</property>
        <property name="User Object Class">{{config['configurations']['nifi-authorizers-env']['ldap-user-object-class']}}</property>
        <property name="User Search Scope">{{config['configurations']['nifi-authorizers-env']['ldap-user-search-scope']}}</property>
        <property name="User Search Filter">{{config['configurations']['nifi-authorizers-env']['ldap-user-search-filter']}}</property>
        <property name="User Identity Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-user-identity-attribute']}}</property>
        <property name="User Group Name Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-user-group-name-attribute']}}</property>
        <property name="User Group Name Attribute - Referenced Group Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-user-group-name-attribute-referenced-group-attribute']}}</property>

        <property name="Group Search Base">{{config['configurations']['nifi-authorizers-env']['ldap-group-search-base']}}</property>
        <property name="Group Object Class">{{config['configurations']['nifi-authorizers-env']['ldap-group-object-class']}}</property>
        <property name="Group Search Scope">{{config['configurations']['nifi-authorizers-env']['ldap-group-search-scope']}}</property>
        <property name="Group Search Filter">{{config['configurations']['nifi-authorizers-env']['ldap-group-search-filter']}}</property>
        <property name="Group Name Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-group-name-attribute']}}</property>
        <property name="Group Member Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-group-member-attribute']}}</property>
        <property name="Group Member Attribute - Referenced User Attribute">{{config['configurations']['nifi-authorizers-env']['ldap-group-name-attribute-referenced-user-attribute']}}</property>
    </userGroupProvider>

    <userGroupProvider>
        <identifier>composite-configurable-user-group-provider</identifier>
        <class>org.apache.nifi.registry.security.authorization.CompositeConfigurableUserGroupProvider</class>
        <property name="Configurable User Group Provider">file-user-group-provider</property>
        <property name="User Group Provider 1">ldap-user-group-provider</property>
    </userGroupProvider>

    <accessPolicyProvider>
        <identifier>file-access-policy-provider</identifier>
        <class>org.apache.nifi.registry.security.authorization.file.FileAccessPolicyProvider</class>
        <property name="User Group Provider">composite-configurable-user-group-provider</property>
        <property name="Authorizations File">{{nifi_registry_internal_config_dir}}/authorizations.xml</property>
        <property name="Initial Admin Identity">{{nifi_registry_initial_admin_id}}</property>
        {{nifi_registry_ssl_config_content}}
    </accessPolicyProvider>

    <authorizer>
        <identifier>managed-authorizer</identifier>
        <class>org.apache.nifi.registry.security.authorization.StandardManagedAuthorizer</class>
        <property name="Access Policy Provider">file-access-policy-provider</property>
    </authorizer>

</authorizers> 
```


Advanced nifi-registry-identity-providers-env
```
<!--
    This file lists the login identity providers to use when running securely. In order
    to use a specific provider it must be configured here and it's identifier
    must be specified in the nifi.properties file.
-->
<identityProviders>
    <provider>
        <identifier>ldap-provider</identifier>
        <class>org.apache.nifi.registry.security.ldap.LdapIdentityProvider</class>
        <property name="Authentication Strategy">{{config['configurations']['nifi-authorizers-env']['ldap-authentication-strategy']}}</property>

        <property name="Manager DN">{{config['configurations']['nifi-authorizers-env']['ldap-manager-dn']}}</property>
        <property name="Manager Password">{{config['configurations']['nifi-authorizers-env']['ldap-manager-password']}}</property>

        <property name="Referral Strategy">{{config['configurations']['nifi-authorizers-env']['ldap-referral-strategy']}}</property>
        <property name="Connect Timeout">{{config['configurations']['nifi-authorizers-env']['ldap-connect-timeout']}}</property>
        <property name="Read Timeout">{{config['configurations']['nifi-authorizers-env']['ldap-read-timeout']}}</property>

        <property name="Url">{{config['configurations']['nifi-authorizers-env']['ldap-url']}}</property>
        <property name="User Search Base">{{config['configurations']['nifi-authorizers-env']['ldap-user-search-base']}}</property>
        <property name="User Search Filter">(sAMAccountName={0})</property>

        <property name="Identity Strategy">{{config['configurations']['nifi-authorizers-env']['ldap-identity-strategy']}}</property>

        <property name="Authentication Expiration">{{config['configurations']['nifi-authorizers-env']['ldap-authentication-expiration']}}</property>
    </provider>

    <!--
    Identity Provider for users logging in with username/password against a Kerberos KDC server.

    'Default Realm' - Default realm to provide when user enters incomplete user principal (i.e. NIFI.APACHE.ORG).
    'Authentication Expiration' - The duration of how long the user authentication is valid for. If the user never logs out, they will be required to log back in following this duration.
    -->
    {% if not security_enabled %}
    <!-- To enable the kerberos-identity-provider remove 2 lines. This is 1 of 2.
    {% endif %}
    <provider>
        <identifier>kerberos-identity-provider</identifier>
        <class>org.apache.nifi.registry.web.security.authentication.kerberos.KerberosIdentityProvider</class>
        <property name="Default Realm">{{nifi_registry_kerberos_realm}}</property>
        <property name="Authentication Expiration">{{nifi_registry_kerberos_authentication_expiration}}</property>
        <property name="Enable Debug">false</property>
    </provider>
    {% if not security_enabled %}
    To enable the kerberos-provider remove 2 lines. This is 2 of 2. -->
    {% endif %}
</identityProviders> 
```
