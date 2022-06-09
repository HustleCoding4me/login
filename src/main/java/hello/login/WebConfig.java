package hello.login;

import hello.login.web.argumentresolver.LoginMemberArgumentResolver;
import hello.login.web.filter.LogFilter;
import hello.login.web.filter.LoginCheckFilter;
import hello.login.web.interceptor.LoginCheckInterceptor;
import hello.login.web.interceptor.Loginterceptor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.Filter;
import java.util.List;

//SpringBoot에서 직접 만든 Filter를 WAS 실행시에 삽입하여준다.
//public class FilterRegistrationBean<T extends Filter> extends AbstractFilterRegistrationBean<T> {}를 빈으로 등록

@Configuration
public class WebConfig implements WebMvcConfigurer {

    public static String[] defaultWhiteList = {"/css/**", "/*.ico", "/error"};

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new LoginMemberArgumentResolver());
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new Loginterceptor())
            .order(1)
            .addPathPatterns("/**")
            .excludePathPatterns(defaultWhiteList);

        registry.addInterceptor(new LoginCheckInterceptor())
            .order(2)
            .addPathPatterns("/**")
            .excludePathPatterns("/", "/members/add", "/login", "/logout")
            .excludePathPatterns(defaultWhiteList);
    }

    //@Bean
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

    //@Bean
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
