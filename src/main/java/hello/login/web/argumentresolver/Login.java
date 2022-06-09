package hello.login.web.argumentresolver;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.PARAMETER)//파라미터 대상으로 사용
@Retention(RetentionPolicy.RUNTIME)//동작할 때 까지 어노테이션이 남아있어야 한다.
public @interface Login {
}
