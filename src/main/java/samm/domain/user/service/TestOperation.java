package samm.domain.user.service;

import javax.inject.Named;
import javax.inject.Singleton;

@Named
@Singleton
public class TestOperation {

    public TestOperation() {
    }

    public String execute() {
        return "hello Bob - it is alive really alive.......";
    }
}
