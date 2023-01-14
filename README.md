# Spring-Security-Demo

As you may have noticed, Spring Security is evolving and the way that we got used to configure it has been changed over time. For example,
We don't have the classical WebSecurityConfigurerAdapter anymore and the usage of authorizeRequests is now deprecated. Instead, it is
suggested to use authorizeHttpRequests. A hint: You can find the default changes in SpringBootWebSecurityConfiguration
file. This file is the one which prevents all the unauthenticated requests, as we add the Spring Security
to our projects.

Because of the above-mentioned situation I created this repository as of 12.01.2023 for those who cannot find many up-to-date resources in the internet
which shows the modern way of implementing Spring Security in their applications.

The repository provides some minimalistic examples about how to configure your HttpSecurity, how to create your custom AuthenticationProviders, your custom Filters and your ObjectPostProcessors.

Apart from that it showcases how you can use OAuth2 with GitHub in your application. To use OAuth2 you should create your GitHub application, and then you should
add your client-id as well as your client-secret to the application.yml file. To not expose those info of mine I created an application-dev.yml file and made git
ignore this file. After that I run the application with dev profile activated. I suggest you to do sth similar and protect your client-id and client-secret.
Otherwise, it would be an irony to expose them as you are learning Spring-Security :))
