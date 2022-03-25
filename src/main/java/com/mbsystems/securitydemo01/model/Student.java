package com.mbsystems.securitydemo01.model;

import lombok.*;

@Data
@NoArgsConstructor(access = AccessLevel.PUBLIC, force = true)
@AllArgsConstructor
@ToString
public class Student {

    private final Integer id;
    private final String name;
}
