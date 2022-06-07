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

3

# 스프링 인터셉터
---

## 스프링 인터셉터란
---

## 요청 로그
---

## 인증 체크
---

## ArgumentResolver 사용
---

# 마무리
---
