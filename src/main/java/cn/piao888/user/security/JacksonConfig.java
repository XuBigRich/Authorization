package cn.piao888.user.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

//@Configuration
public class JacksonConfig {
    
    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.addMixIn(UserInfo.class, UserInfoMixin.class);
//        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
//                .allowIfBaseType("cn.piao888.user.security.UserInfo") // 仅允许特定基础类型
//                .build();
//        objectMapper.activateDefaultTyping(ptv,ObjectMapper.DefaultTyping.NON_FINAL);
        return objectMapper;
    }
}