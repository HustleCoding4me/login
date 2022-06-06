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
## 인증 체크
---



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
