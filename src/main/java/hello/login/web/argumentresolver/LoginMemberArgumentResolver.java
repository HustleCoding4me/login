package hello.login.web.argumentresolver;

import hello.login.domain.member.Member;
import hello.login.web.SessionConst;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Slf4j
public class LoginMemberArgumentResolver implements HandlerMethodArgumentResolver {
  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    log.info("supportsParameter 실행");

    boolean hasLoginAnnotation = parameter.hasParameterAnnotation(Login.class);//파라미터가 로그인 Anno를 가지고 있냐
    boolean hasMemberType = Member.class.isAssignableFrom(parameter.getParameterType());//파라미터의 Class가 해당 타입인지
    return hasLoginAnnotation && hasMemberType;//Anno가 붙어있고 Member.class면 실행
  }

  @Override
  public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
    log.info("resolveArgument 실행");

    HttpServletRequest nativeRequest = (HttpServletRequest) webRequest.getNativeRequest();
    HttpSession session = nativeRequest.getSession();
    if (session == null) {
      return null;
    }
    return session.getAttribute(SessionConst.LOGIN_MEMBER);
  }
}
