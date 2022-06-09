# 서블릿 필터

---

## 서블릿 필터란

---

주로 `웹`과 관련된 **공통관심사항** 을 처리할 때 사용한다.

> <h3> why?</h3> Http의 헤더나 URL의 정보들이 필요한데, 서블릿 필터, 스프링 인터셉터는 `HttpServletRequest` 등 웹에 필요한 기능들을 제공한다. + 웹과 관련된 많은 기능들 제공.


* AOP는 메서드 호출 시에 어떤 것이 호출되고 이런 것들만 알 수 있다.

* 공통 관심사항 : Application의 여러 로직에서 공통적으로 적용되어야 하는 기능 (ex : 인증 Authentication, 로그인 처리)


> 필터 작동 순서

```java
//기본 작동 순서
HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 컨트롤러

//제한 
        HTTP 요청 -> WAS -> 필터(부적절 요청 판단, 서블릿 요청 X) 끝

//체인 
        HTTP 요청 -> WAS -> 필터1 -> 필터2 -> 필터3 -> 서블릿 -> 컨트롤러
```



> 필터 인터페이스

```java
public interface Filter {

    //필터 초기화, 초기 필터 생성시에 호출
    public default void init(FilterConfig filterConfig) throws ServletException {}

    //요청이 올 때 마다 해당 메서드가 호출된다.
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException;

    //필터 종료시 호출
    public default void destroy() {}
}
```



## 요청 로그

---

Filter 적용 테스트로 log를 남기는 방법을 알아보자.

> 주의사항, `import javax.servlet.Filter` 를 구현해야 한다.

1. interface `Filter` 구현체 생성

```java
import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.UUID;

@Slf4j
public class LogFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        log.info("log filter init");
    }

    @Override
    public void destroy() {
        log.info("log filter destory");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("log filter doFilter");

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestURI = httpRequest.getRequestURI();

        String uuid = UUID.randomUUID().toString();

        try {
            log.info("REQUEST [{}][{}]", uuid, requestURI);
            //다음 Filter의 기능 실행 (체인 or 디스패쳐 서블릿에세 기능 넘기기)
            chain.doFilter(request,response);
        } catch (Exception e) {
            throw e;
        } finally {
            log.info("RESPONSE [{}] [{}]", uuid, requestURI);
        }
    }
}
```

* `chain.doFilter(request,response)` : 다음 Filter의 기능 실행 (다음 filter 체인 or 디스패쳐 서블릿에 기능 넘기기)

2. SpringBoot의 `FilterRegistrationBean` 에 등록

```java
@Configuration
public class WebConfig {
    @Bean
    public FilterRegistrationBean logFilter() {
        FilterRegistrationBean<Filter> filterFilterRegistrationBean = new FilterRegistrationBean<>();

        //만든 로그필터 등록
        filterFilterRegistrationBean.setFilter(new LogFilter());

        //순서 등록
        filterFilterRegistrationBean.setOrder(1);

        //URL 패턴 적용
        filterFilterRegistrationBean.addUrlPatterns("/*");

        return filterFilterRegistrationBean;
    }
}

```

* SpringBoot에서 직접 만든 Filter를 WAS 실행시에 삽입하여준다.
* `public class FilterRegistrationBean<T extends Filter> extends AbstractFilterRegistrationBean<T> {}` 를 빈으로 등록


## 인증 체크

---

허가되지 않은 URI에 접근하지 못하게 만들어보자. (로그인 이전에 차단하고 싶은 URI)



1. LoginCheckFilter 생성

```java
import hello.login.web.SessionConst;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.PatternMatchUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
public class LoginCheckFilter implements Filter {

    private static final String[] whiteList = {"/", "/members/add", "/login", "/logout", "/css/*"};

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestURI = httpRequest.getRequestURI();

        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        try {
            log.info("인증 체크 필터 시작{}", requestURI);


            if (isLoginCheckPath(requestURI)) {
                log.info("인증 체크 로직 실행{}", requestURI);
                HttpSession session = httpRequest.getSession(false);
                if (session == null || session.getAttribute(SessionConst.LOGIN_MEMBER) == null) {
                    log.info("미인증 사용자 요청{}", requestURI);
                    //로그인으로 redirect
                    httpServletResponse.sendRedirect("/login?redirectURL=" + requestURI);
                    return;
                }
            }
            chain.doFilter(request, response);
        } catch (Exception e) {
            throw e;
        } finally {
            log.info("인증 체크 필터 종료 {} ", requestURI);
        }
    }

    /**
     * 화이트 리스트의 경우 인증 체크 X
     */
    private boolean isLoginCheckPath(String requestUri) {
        return !PatternMatchUtils.simpleMatch(whiteList, requestUri);
    }
}
```

* `HttpServletResponse httpServletResponse = (HttpServletResponse) response;`  : 더 강력한 기능을 위해 `ServletRequest`의 구현체로 다운캐스팅

* `if (isLoginCheckPath(requestURI)) {` : 허용되지 않은 URI로 요청이 들어오면, 작동.

  -> 코드에서는 `"/", "/members/add", "/login", "/logout", "/css/*"` 요청만 허가

* ```
  httpServletResponse.sendRedirect("/login?redirectURL=" + requestURI);
  return;
  추후에 로그인 이후, 자연스럽게 요청했던 URI로 redirect 시켜주기 위해 요청 URI저장,
  바로 중지하는 모습. (`chain.doFilter`가 실행되지 않으면 요청은 그대로 중지)
  ```



> ```java
> PatternMatchUtils.simpleMatch(whiteList, requestUri);
> //"/uri" 로 패턴에 맞나 안맞나 체크하여 boolean으로 return 해준다.
> ```



2. Filter를 Configuration에 Bean으로 등록

```java
@Configuration
public class WebConfig {    
	@Bean
    public FilterRegistrationBean LoginCheckFilter() {
        FilterRegistrationBean<Filter> filterFilterRegistrationBean = new FilterRegistrationBean<>();

        //만든 로그필터 등록
        filterFilterRegistrationBean.setFilter(new LoginCheckFilter());

        //순서 등록
        filterFilterRegistrationBean.setOrder(2);

        //URL 패턴 적용
        filterFilterRegistrationBean.addUrlPatterns("/*");

        return filterFilterRegistrationBean;
    }
}
```



3. Controller 구현

   -> Filter에 막혀 Login 페이지로 넘어간 URI 저장하여 바로 Login할 경우, 로그인 통과시 바로 해당 페이지 보여주게 작업

```java
    @PostMapping("/login")
    public String loginV4(@Validated @ModelAttribute LoginForm loginForm, BindingResult bindingResult, HttpServletResponse response, @RequestParam(defaultValue = "/") String redirectURL) {
        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }

        Member loginMember = loginService.login(loginForm.getLoginId(), loginForm.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }

        //로그인 성공처리 TODO
        sessionManager.createSession(loginMember, response);

        return "redirect:"+redirectURL;
    }
```

* `@Validated @ModelAttribute LoginForm loginForm, BindingResult bindingResult` : LoginForm 객체에 지정해둔 Validation 어노테이션들의 규약조건에 따라, 맞지 않는 것들을 @Validated 검증한단 의미. BindingResult 객체에 오류들을 담아 자동으로 넣어준다.
* `HttpServletResponse response` : Session 처리를 위해 Response를 받음
* `@RequestParam(defaultValue = "/") String redirectURL` : LoginCheckFilter에서 Login 검증이 되지 않은 상태에서 잘못된 접근을 하면,  ("/login?redirectURL=" + requestURI); 경로로 redirect 시키는데, redirectURL이 없으면 기본 /, 있으면 직전 요청 저장하기 위한 용도.



# 스프링 인터셉터

---

* **서블릿 필터** vs **스프링 인터셉터**

|               서블릿 필터                |                       스프링 인터셉터                        |
| :--------------------------------------: | :----------------------------------------------------------: |
|            서블릿이 제공한다             |                      스프링 MVC가 제공                       |
| WAS와 디스패쳐 서블릿 사이에서 작동한다. |         디스패쳐 서블릿과 컨트롤러 호출 직전에 사용          |
|                                          |       URL 패턴이 더 정밀해졌다. (MVC 이후 나왔기 때문)       |
|      doFilter만 호출하여 사용한다.       | preHandle, postHandle,afterCompletion 등 호출 시점이 더 정교하다. |



**스프링 인터셉터 작동 순서**



* 기본 흐름

```markdown
HttP 요청 -> WAS -> 필터 -> 서블릿 -> **스프링 인터셉터** -> 컨트롤러
```

* 제한

```markdown
HttP 요청 -> WAS -> 필터 -> 서블릿 -> **스프링 인터셉터** (부적절 접근 Controller 호출 X) //비 로그인
```

* 체인

```markdown
HttP 요청 -> WAS -> 필터 -> 서블릿 -> log 인터셉터1 -> loginCheck 인터셉터2 -> 컨트롤러
```



## 스프링 인터셉터란

---



**인터페이스**

```java
public interface HandlerInterceptor {
default boolean preHandle(HttpServletRequest request, HttpServletResponse 
response,
 Object handler) throws Exception {}
default void postHandle(HttpServletRequest request, HttpServletResponse 
response,
 Object handler, @Nullable ModelAndView modelAndView)
throws Exception {}
default void afterCompletion(HttpServletRequest request, HttpServletResponse 
response,
 Object handler, @Nullable Exception ex) throws
Exception {}
}
```

* `preHandle` : 컨트롤러 호출 전 (사전 false인 경우 진행 중지)
* `postHandle` : 컨트롤러 호출 후 (Controller 수행 후라 어떤 MV 가 들어있는지도 return 된다.)
* `afterCompletion` : 요청 완료 이후 (뷰 렌더링 이후 예외가 발생해도 호출), 어떤 오류가 터졌는지 찍을 수도 있다.

Http요청 -> Dispatcher Servlet -> `1.preHandle` -> Controller ->`2.postHandle` -> View -> `3.afterCompletion`



1.preHandle 에서 예외가 발생하면, false를 return하여 바로 작동이 끝난다.

2.Controller에서 예외가 발생하면, postHandle을 호출하지 않고 작동이 끝난다.

3.afterCompletion은 앞에서 예외가 터져도 무조건 호출된다. (예외와 함께 전달)





## 요청 로그

**적용할 Interceptor 생성하기** 

```java
@Slf4j
public class Loginterceptor implements HandlerInterceptor {

  public static final String LOG_ID = "logId";

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    String requestURI = request.getRequestURI();
    String uuid = UUID.randomUUID().toString();

    request.setAttribute(LOG_ID,uuid);

    if (handler instanceof HandlerMethod) {
      HandlerMethod hm = (HandlerMethod) handler;
    }

    //@RequestMapping : HandlerMethod
    //정적 리소스 : ResourceHttpRequestHandler

    log.info("REQUEST [{}] [{}] [{}] [{}]", uuid, requestURI, handler);
    return true;//실 handler가 호출되게 true
  }

  @Override
  public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
    log.info("postHandler [{}]", modelAndView);
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
    String requestURI = request.getRequestURI();
    String uuid = (String) request.getAttribute(LOG_ID);
    log.info("RESPONSE [{}][{}][{}]", uuid, requestURI, handler, ex);
    if (ex != null) {
      log.error("afterCOmpletion Error!");
    }

  }
}
```

* `implements HandlerInterceptor` : HandlerInterceptor를 구현해줘야 한다. (Spring과의 약속~)

* `preHandle` :  uuid를 만들어서 요청 Request에 Attribute로 담아준다. 요청 건수마다 개별 생성되는 request의 특성상, 요청이 종료될 때 까지 유지된다.

  *     if (handler instanceof HandlerMethod) {
          HandlerMethod hm = (HandlerMethod) handler;
        }
        
        보통 @RequestMapping 류의 동적 리소스들은 모두 HandlerMethod를 받는다. 
        
        ![Screen Shot 2022-06-09 at 4 34 27 PM](https://user-images.githubusercontent.com/37995817/172791059-5c3cd9ca-20e8-4ee6-91aa-722c21091faf.png)


    이렇게 많은 정보들이 담겨 있어서 사용 가능!

    

    

* `afterCompletion` :  오류가 나도 실행되기 때문에, 오류 log를 남기기 위해서는 View까지 다녀온 이후 실행되는  `afterCompletion` 에 적어야 한다. 



**생성한 Interceptor 적용하기**

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new Loginterceptor())
            .order(1)
            .addPathPatterns("/**")
            .excludePathPatterns("/css/**", "/*.ico", "/error");
    }
}
```

* `WebMvcConfigurer` : `@Configuration` 파일에서 Interceptor를 달아줄 수 있는 메서드가 있는 인터페이스이다. 해당 인터페이스에서 `addInterceptors` 를 구현하여 사용한다.
* `InterceptorRegistry` : registry에 체인 형식으로 adding을 해주는데, 여기에 우리가 만든 Interceptor를 생성하여 넣어주고, 동작 순서(`order`) ,인터셉터 작동할 패턴(`addPathPatterns`), 예외 패턴(`excludePathPatterns`)를 사용한다.

#### Q: excludePathPAtterns를 매번 저렇게 적어줘야 하나? 공통관리로 빼어서 chain에서 제거해주는 방법이 있을 것 같다.





## 인증 체크

---

## ArgumentResolver 사용

---

# 마무리
