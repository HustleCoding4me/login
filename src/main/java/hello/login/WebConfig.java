package hello.login;

import hello.login.web.filter.LogFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;

//SpringBoot에서 직접 만든 Filter를 WAS 실행시에 삽입하여준다.
//public class FilterRegistrationBean<T extends Filter> extends AbstractFilterRegistrationBean<T> {}를 빈으로 등록

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
