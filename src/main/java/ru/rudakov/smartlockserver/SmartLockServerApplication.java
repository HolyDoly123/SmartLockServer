package ru.rudakov.smartlockserver;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableEncryptableProperties
public class SmartLockServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SmartLockServerApplication.class, args);
    }

}
