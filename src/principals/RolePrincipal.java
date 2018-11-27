package principals;

import java.security.Principal;

public class RolePrincipal implements Principal {
	  
	  private String name;
	  
	  public RolePrincipal(String name) {
	    super();
	    this.name = name;
	  }

	  public void setName(String name) {
	    this.name = name;
	  }

	  public String getName() {
		    return name;
		  }

}