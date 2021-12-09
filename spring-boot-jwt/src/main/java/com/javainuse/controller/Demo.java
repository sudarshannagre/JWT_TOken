package com.javainuse.controller;

import org.springframework.beans.factory.annotation.Autowired;

import com.javainuse.config.JwtTokenUtil;

import io.jsonwebtoken.Claims;


public class Demo {

	@Autowired
	private static JwtTokenUtil jwtTokenUtil;
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Claims c = jwtTokenUtil.getAllClaimsFromToken("");
		System.out.println(c);
	}

}
