package se.diabol.jenkins.plugins;

import com.atlassian.crowd.exception.*;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.CrowdClient;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import org.acegisecurity.*;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;

import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

public class JiraAuthRealm extends AbstractPasswordBasedSecurityRealm {

    private static final Logger LOG = Logger.getLogger(JiraAuthRealm.class.getName());


    private String jiraUrl;
    private String username;
    private String password;

    private transient CrowdClient crowdClient;


    @DataBoundConstructor
    public JiraAuthRealm(String jiraUrl, String username, String password) {
        this.jiraUrl = jiraUrl;
        this.username = username;
        this.password = password;
    }

    public String getJiraUrl() {
        return jiraUrl;
    }

    public void setJiraUrl(String jiraUrl) {
        this.jiraUrl = jiraUrl;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        try {
            getCrowdClient().authenticateUser(username, password);
            UserDetails userDetails = loadUserByUsername(username);
            LOG.info("User " + username + " successfully logged in");
            return userDetails;
        } catch (UserNotFoundException e) {
            LOG.info("User " + username + " failed to login due to unknown username");
            throw new BadCredentialsException(e.getMessage(), e);
        } catch (InactiveAccountException e) {
            LOG.info("User " + username + " failed to login due to blocked account");
            throw new DisabledException(e.getMessage(), e);
        } catch (ExpiredCredentialException e) {
            LOG.info("User " + username + " failed to login due to expired credentials");
            throw new CredentialsExpiredException(e.getMessage(), e);
        } catch (ApplicationPermissionException e) {
            throw new AuthenticationServiceException("Application permission error", e);
        } catch (InvalidAuthenticationException e) {
            LOG.info("User " + username + " failed to login due to invalid password");
            throw new BadCredentialsException(e.getMessage(), e);
        } catch (OperationFailedException e) {
            throw new AuthenticationServiceException("Application operation failed error", e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        try {
            List<String> groupNames = getCrowdClient().getNamesOfGroupsForUser(username, 0, 1000);
            return new JiraUserDetails(username, null, groupNames);
        } catch (OperationFailedException e) {
            throw new DataAccessResourceFailureException("OperationFailed", e);
        } catch (InvalidAuthenticationException e) {
            throw new DataAccessResourceFailureException("InvalidAuthentication", e);
        } catch (ApplicationPermissionException e) {
            throw new DataAccessResourceFailureException("ApplicationPermission", e);
        } catch (UserNotFoundException e) {
            throw new UsernameNotFoundException("Username: " + username, e);
        }
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupname) throws UsernameNotFoundException, DataAccessException {
        try {
            final Group group = getCrowdClient().getGroup(groupname);
            return new GroupDetails() {
                @Override
                public String getName() {
                    return group.getName();
                }
            };
        } catch (GroupNotFoundException e) {
            throw new DataAccessResourceFailureException("GroupNotFound", e);
        } catch (OperationFailedException e) {
            throw new DataAccessResourceFailureException("OperationFailed", e);
        } catch (InvalidAuthenticationException e) {
            throw new DataAccessResourceFailureException("InvalidAuthentication", e);
        } catch (ApplicationPermissionException e) {
            throw new DataAccessResourceFailureException("ApplicationPermission", e);
        }
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    private synchronized CrowdClient getCrowdClient() {
        if (crowdClient == null) {
            final Properties properties = new Properties();
            properties.setProperty("crowd.server.url", jiraUrl);
            properties.setProperty("application.name", username);
            properties.setProperty("application.password", password);
            properties.setProperty("session.validationinterval", "5");

            final ClientProperties clientProperties = ClientPropertiesImpl.newInstanceFromProperties(properties);
            final RestCrowdClientFactory restCrowdFactory = new RestCrowdClientFactory();
            crowdClient = restCrowdFactory.newInstance(clientProperties);
        }
        return crowdClient;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getDisplayName() {
            return "Jira Security Realm uses Jira as the User database";
        }

    }


}
