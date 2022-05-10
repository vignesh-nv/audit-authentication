package com.audit.authentication.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
	
	/**
	 * This is a private field which is used to represent the userid for user login
	 * credentials. The data type is String.
	 */
	private String uid;

	/**
	 * This is a private field which is used to represent whethet the token is valid
	 * or not. The data type is boolean.
	 */
	
	private boolean isValid;
	}
