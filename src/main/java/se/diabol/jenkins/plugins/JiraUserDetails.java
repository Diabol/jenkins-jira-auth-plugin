package se.diabol.jenkins.plugins;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.UserDetails;

import java.util.List;

public class JiraUserDetails implements UserDetails {

    private String username;
    private String password;

    private List<String> groupNames;


    public JiraUserDetails(String username, String password, List<String> groupNames) {
        this.username = username;
        this.password = password;
        this.groupNames = groupNames;
    }

    public GrantedAuthority[] getAuthorities() {
        GrantedAuthority[] result = new GrantedAuthority[groupNames.size()];
        for (int i = 0; i < groupNames.size(); i++) {
            String group = groupNames.get(i);
            result[i] = new GrantedAuthorityImpl(group);
        }
        return result;
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }

    public boolean isAccountNonExpired() {
        return true;
    }

    public boolean isAccountNonLocked() {
        return true;
    }

    public boolean isCredentialsNonExpired() {
        return true;
    }

    public boolean isEnabled() {
        return true;
    }
}
