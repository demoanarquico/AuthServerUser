package cl.bci.auth.security.config.entity;


import java.io.Serializable;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinColumns;
import javax.persistence.OneToMany;
import javax.persistence.Table;

@Entity
@Table(name = "users")
public class UserEntity implements Serializable {
	@Id
	@Column(name = "id" )
	private Integer id;
	
	@Column(name = "username" )
	private String userName;
	
	@Column(name = "password" )
	private String password;
	
	@Column(name = "enabled" )
	private boolean enabled;
	
	 @OneToMany(cascade=CascadeType.ALL)
	    @JoinColumns ({
	        @JoinColumn(name="username", referencedColumnName = "username")
	    })
	private List<AuthorityEntity> authorities;

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public List<AuthorityEntity> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(List<AuthorityEntity> authorities) {
		this.authorities = authorities;
	}

	@Override
	public String toString() {
		return "UserEntity [id=" + id + ", userName=" + userName + ", password=" + password + ", enabled=" + enabled
				+ ", authorities=" + authorities + "]";
	}

	

}