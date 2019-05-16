﻿using System;
using System.Linq.Expressions;
using System.Reflection;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Netezos.Rpc
{
    /// <summary>
    /// Rpc query to get a json object
    /// </summary>
    public class RpcObject : RpcQuery
    {
        #region static
        internal delegate T Creator<T>(RpcQuery baseQuery, string append);

        internal static Creator<T> GetCreator<T>() where T : RpcObject
        {
            var ctor = typeof(T).GetConstructor(
                   BindingFlags.NonPublic | BindingFlags.Instance,
                   null,
                   new[] { typeof(RpcQuery), typeof(string) },
                   null);

            if (ctor == null)
                throw new Exception($"Can't find apropriate constructor in {typeof(T)}");

            var args = new[]
            {
                Expression.Parameter(typeof(RpcQuery)),
                Expression.Parameter(typeof(string))
            };

            var lambda = Expression.Lambda(
                typeof(Creator<T>),
                Expression.New(ctor, args),
                args);

            return (Creator<T>)lambda.Compile();
        }
        #endregion

        internal RpcObject(RpcClient client, string query) : base(client, query) { }
        internal RpcObject(RpcQuery baseQuery, string append) : base(baseQuery, append) { }

        /// <summary>
        /// Executes the query and returns the json object
        /// </summary>
        /// <returns></returns>
        public async Task<JToken> GetAsync() => await Client.GetJson(Query);

        /// <summary>
        /// Executes the query and returns the json object, deserealized to the specified type
        /// </summary>
        /// <typeparam name="T">Type of the object to deserialize to</typeparam>
        /// <returns></returns>
        public async Task<T> GetAsync<T>() => await Client.GetJson<T>(Query);

        public override string ToString() => Query;
    }
}