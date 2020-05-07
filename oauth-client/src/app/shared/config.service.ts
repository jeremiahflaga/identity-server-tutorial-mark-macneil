import { Injectable } from '@angular/core';
 
@Injectable()
export class ConfigService {    

    constructor() {}

    get authBaseURI() {
        return 'http://localhost:64082';
    }    
     
    get authApiURI() {
        return `${this.authBaseURI}/api`;
    }    
     
    get resourceApiURI() {
        return 'http://localhost:49252/api';
    }  
}